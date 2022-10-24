#include <optional>
#include <string>
#include <unordered_map>

#include <boost/outcome.hpp>

#include <unicode/unistr.h>
#include <unicode/errorcode.h>
#include <unicode/ucnv.h>

#define FUSE_USE_VERSION 35

#include <fuse.h>
#include <fuse_lowlevel.h>
#include <fuse_log.h>

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std::literals;
namespace outcome = BOOST_OUTCOME_V2_NAMESPACE;

using icu::UnicodeString;

namespace
{
	// Represents an always-failed state for type safety
	struct error
	{
		int err;

		constexpr explicit error(int neg_errno) : err(neg_errno) {}

		static error from_errno()
		{
			return error{-errno};
		}

		static outcome::failure_type<error> failure_from_errno()
		{
			return outcome::failure(from_errno());
		}
	};

	// Represents a specific failure or a generic success
	struct errno_or_success
	{
		int err;

		errno_or_success(outcome::success_type<void>) : err(0) {}
		errno_or_success(outcome::failure_type<error> e) : err(e.error().err) {}
		explicit errno_or_success(int neg_errno) : err(neg_errno) {}

		constexpr bool has_value() const noexcept
		{
			return err == 0;
		}

		constexpr int assume_value() const noexcept
		{
			return 0;
		}

		constexpr error assume_error() const noexcept
		{
			return error{err};
		}

		static errno_or_success from_errno(bool is_success)
		{
			if (is_success)
				return outcome::success();
			return error::failure_from_errno();
		}
	};

	struct errno_or_nonnegative
	{
		int err;

		errno_or_nonnegative(outcome::success_type<int> i) : err(i.value()) {}
		errno_or_nonnegative(outcome::failure_type<error> e) : err(e.error().err) {}
		explicit errno_or_nonnegative(int neg_errno_or_val) : err(neg_errno_or_val) {}

		constexpr bool has_value() const noexcept
		{
			return err >= 0;
		}

		constexpr int assume_value() const noexcept
		{
			return err;
		}

		constexpr error assume_error() const noexcept
		{
			return error{err};
		}

		static errno_or_nonnegative from_errno(int value)
		{
			if (value >= 0)
				return outcome::success(value);
			return error::failure_from_errno();
		}
	};

	template <class T>
	using errno_result = outcome::result<T, error, outcome::policy::terminate>;

	struct raii_fd
	{
		static constexpr int invalid = -1;

		int fd;

		explicit raii_fd(int fd_) : fd(fd_) {}
		raii_fd(raii_fd &&fd_) : fd(fd_.fd)
		{
			fd_.fd = invalid;
		}

		constexpr bool valid() const
		{
			return fd != invalid;
		}

		constexpr explicit operator bool() const
		{
			return valid();
		}

		constexpr explicit operator int() const
		{
			return fd;
		}

		~raii_fd()
		{
			if (valid())
				close(fd);
		}
	};

	struct raii_dir
	{
		DIR *dir;

		explicit raii_dir(raii_fd &&dir_fd) : dir(fdopendir(dir_fd.fd))
		{
			if (valid())
				// dir now own the fd, so dir_fd shouldn't close it
				dir_fd.fd = raii_fd::invalid;
		}

		raii_dir(raii_dir &&d) : dir(d.dir)
		{
			d.dir = nullptr;
		}

		constexpr bool valid() const
		{
			return dir != nullptr;
		}

		constexpr operator bool() const
		{
			return valid();
		}

		dirent *next_entry()
		{
			if (!valid())
				return nullptr;
			errno = 0;
			return readdir(dir);
		}

		~raii_dir()
		{
			if (valid())
				closedir(dir);
		}
	};

	struct config
	{
		const char *mount_dir;
		bool use_backslash_sep = true;
	};

	struct folded_leaf
	{
		std::string dir;
		UnicodeString leaf_name;
	};

	struct folded_leaf_ref
	{
		std::string_view dir;
		const UnicodeString &leaf_name;
	};

	bool operator==(const folded_leaf &l1, const folded_leaf &l2)
	{
		return l1.dir == l2.dir && l1.leaf_name == l2.leaf_name;
	}

	bool operator==(const folded_leaf &l1, const folded_leaf_ref &l2)
	{
		return l1.dir == l2.dir && l1.leaf_name == l2.leaf_name;
	}

	bool operator==(const folded_leaf_ref &l1, const folded_leaf_ref &l2)
	{
		return l1.dir == l2.dir && l1.leaf_name == l2.leaf_name;
	}

	struct leaf_hash
	{
		using is_transparent = void;

		std::size_t operator()(const folded_leaf &leaf) const noexcept
		{
			return std::hash<std::string_view>{}(leaf.dir) + leaf.leaf_name.hashCode();
		}

		std::size_t operator()(const folded_leaf_ref &leaf) const noexcept
		{
			return std::hash<std::string_view>{}(leaf.dir) + leaf.leaf_name.hashCode();
		}
	};

	struct existing_path
	{
		std::string path;
	};

	struct maybe_new_path
	{
		std::string real_path;
		std::optional<folded_leaf> folded_path;
	};

	struct data
	{
		const config &c;
		int root_fd;

		UConverter *utf8_converter;
		std::unordered_map<folded_leaf, std::string, leaf_hash, std::equal_to<>> path_maps;

		data(const config &c_) noexcept : c(c_)
		{
			if (c.mount_dir)
			{
				root_fd = open(c.mount_dir, O_RDONLY | O_DIRECTORY);
			}
			else
			{
				fuse_log(FUSE_LOG_ERR, "error: no mountpoint specified\n");
			}

			icu::ErrorCode ec;
			utf8_converter = ucnv_open("utf-8", ec);
			ec.assertSuccess();

			populate_maps();
		}

		static data *get() noexcept
		{
			auto ctx = fuse_get_context();
			auto d = reinterpret_cast<data *>(ctx->private_data);
			return d;
		}

		errno_result<raii_fd> open_rel(const char *path, int flags) const noexcept
		{
			raii_fd ret(::openat(root_fd, path, flags));
			if (!ret)
				return error::failure_from_errno();
			return ret;
		}

		errno_result<raii_fd> open_rel(const char *path, int flags, mode_t mode) const noexcept
		{
			raii_fd ret(::openat(root_fd, path, flags, mode));
			if (!ret)
				return error::failure_from_errno();
			return ret;
		}

		errno_or_success stat_rel(const char *path, struct stat *buf, int flags) const noexcept
		{
			auto ret = ::fstatat(root_fd, path, buf, flags);
			return errno_or_success::from_errno(ret == 0);
		}

		errno_or_success mkdir_rel(const char *path, mode_t mode) noexcept
		{
			auto ret = ::mkdirat(root_fd, path, mode);
			return errno_or_success::from_errno(ret == 0);
		}

		errno_or_success unlink_rel(const char *path, int flags) noexcept
		{
			auto ret = ::unlinkat(root_fd, path, flags);
			return errno_or_success::from_errno(ret == 0);
		}

		errno_or_success symlink_rel(const char *path, const char *target) noexcept
		{
			auto ret = ::symlinkat(target, root_fd, path);
			return errno_or_success::from_errno(ret == 0);
		}

		errno_or_nonnegative readlink_rel(const char *path, char *buf, size_t len) noexcept
		{
			auto ret = ::readlinkat(root_fd, path, buf, len);
			return errno_or_nonnegative::from_errno(ret);
		}

		errno_or_success rename_rel(const char *path_from, const char *path_to, int flags) noexcept
		{
			auto ret = ::renameat2(root_fd, path_from, root_fd, path_to, flags);
			return errno_or_success::from_errno(ret);
		}

		std::optional<UnicodeString> to_unicode(std::string_view sv) const noexcept
		{
			icu::ErrorCode ec;
			UnicodeString ustr(sv.data(), sv.size(), utf8_converter, ec);
			if (ustr.isBogus())
				return std::nullopt;
			ustr.foldCase();
			return ustr;
		}

		errno_result<std::string> resolve_file(std::string &&dir, std::string_view file) const noexcept
		{
			auto uni = to_unicode(file);
			if (!uni)
			{
				if (!dir.empty())
					dir += '/';
				dir += file;
				return outcome::success(std::move(dir));
			}
			folded_leaf_ref key {.dir = dir, .leaf_name = *uni};
			auto i = path_maps.find(key);
			if (i == end(path_maps))
				return outcome::failure(-ENOENT);
			dir = i->second;
			return outcome::success(std::move(dir));
		}

		void populate_map_from_dir(std::string path, raii_dir &dir)
		{
			auto orig_size = path.size();
			while (auto entry = dir.next_entry())
			{
				std::string_view name(entry->d_name);
				auto uni = to_unicode(name);
				if (uni)
				{
					auto &entry = path_maps[folded_leaf{.dir = path, .leaf_name = *uni}];
					entry.reserve(path.size() + 1 + name.size());
					entry = path;
					if (!entry.empty())
						entry += '/';
					entry += name;
				}
				auto is_dir = [&]() -> std::optional<bool> {
					// We only want to recurse into child directories
					if (name == "."sv || name == ".."sv)
						return false;
					switch (entry->d_type)
					{
					case DT_BLK:
					case DT_CHR:
					case DT_FIFO:
					case DT_LNK:
					case DT_REG:
					case DT_SOCK:
						return false;
					case DT_DIR:
						return true;
					default:
						return std::nullopt;
					}
				}();
				if (!is_dir)
				{
					// TODO: Call fstatat
				}
				if (is_dir && *is_dir)
				{
					if (!path.empty())
						path += '/';
					path += name;
					raii_fd fd(openat(root_fd, path.c_str(), O_RDONLY | O_DIRECTORY));
					if (fd)
					{
						raii_dir dir_fd(std::move(fd));
						if (dir_fd)
							populate_map_from_dir(path, dir_fd);
					}
					path.resize(orig_size);
				}
			}
		}

		void populate_maps() noexcept
		{
			std::string path;
			path_maps.emplace(folded_leaf{.dir = "", .leaf_name = {}}, "");

			raii_fd fd(openat(root_fd, ".", O_RDONLY | O_DIRECTORY));
			if (!fd)
				return;
			raii_dir dir_fd(std::move(fd));
			if (!dir_fd)
				return;
			populate_map_from_dir(path, dir_fd);
		}

		// Calls func on each directory in the path and returns the last component
		template <class Func>
		errno_result<std::string_view> foreach_dir(std::string_view path, Func &&func) const noexcept
		{
			auto extract_component = [&]{
				while (!path.empty())
				{
					if (path.front() == '/')
						path.remove_prefix(1);
					else if (c.use_backslash_sep && path.front() == '\\')
						path.remove_prefix(1);
					else
						break;
				}
				auto sep_pos = [&] {
					if (c.use_backslash_sep)
						return path.find_first_of("/\\");
					return path.find('/');
				}();
				auto ret = path.substr(0, sep_pos);
				if (sep_pos > path.size())
					path.remove_prefix(path.size());
				else
					path.remove_prefix(sep_pos);
				return ret;
			};
			while (true)
			{
				auto comp = extract_component();
				if (path.empty())
					return comp;
				BOOST_OUTCOME_TRYV(func(comp));
			}
		}

		struct lookup_ret
		{
			std::string dir;
			std::string_view leaf_name;
		};

		errno_result<lookup_ret> lookup_path(std::string_view path) const noexcept
		{
			std::string real_path;
			real_path.reserve(path.size());
			BOOST_OUTCOME_TRY(auto leaf, foreach_dir(path, [&](std::string_view comp) -> errno_or_success {
				BOOST_OUTCOME_TRY(auto path, resolve_file(std::move(real_path), comp));
				real_path = std::move(path);
				return outcome::success();
			}));
			return outcome::success(lookup_ret{.dir = std::move(real_path), .leaf_name = leaf});
		}

		errno_result<existing_path> to_existing_path(const char *path) const noexcept
		{
			std::string_view path_sv(path);
			BOOST_OUTCOME_TRY(auto lookup, lookup_path(path_sv));
			BOOST_OUTCOME_TRY(auto final_path, resolve_file(std::move(lookup.dir), lookup.leaf_name));
			if (final_path.empty())
				final_path = "."s;
			return outcome::success(existing_path{final_path});
		}

		errno_result<maybe_new_path> to_maybe_new_path(const char *path) const noexcept
		{
			std::string_view path_sv(path);
			BOOST_OUTCOME_TRY(auto lookup, lookup_path(path_sv));

			auto uni = to_unicode(lookup.leaf_name);
			if (!uni)
			{
				auto real_path = std::move(lookup.dir);
				if (!real_path.empty())
					real_path += '/';
				real_path += lookup.leaf_name;
				return outcome::success(maybe_new_path{.real_path=std::move(real_path), .folded_path=std::nullopt});
			}

			folded_leaf key {.dir = std::move(lookup.dir), .leaf_name = std::move(*uni)};
			auto i = path_maps.find(key);
			if (i == end(path_maps))
			{
				auto real_path = key.dir;
				if (!real_path.empty())
					real_path += '/';
				real_path += lookup.leaf_name;
				return outcome::success(maybe_new_path{.real_path=std::move(real_path), .folded_path=std::move(key)});
			}
			const auto &real_path = i->second;
			if (real_path.empty())
				return outcome::success(maybe_new_path{.real_path="."s, .folded_path=std::move(key)});
			return outcome::success(maybe_new_path{.real_path=real_path, .folded_path=std::move(key)});
		}

		template <class T>
		errno_result<T> convert(const char *path) const noexcept;

		errno_or_success getattr(const existing_path &path, struct stat *stat_buf, fuse_file_info *fi) noexcept
		{
			return stat_rel(path.path.c_str(), stat_buf, AT_SYMLINK_NOFOLLOW);
		}

		errno_or_success readdir(const existing_path &path, void *buf, fuse_fill_dir_t filler, off_t offset, fuse_file_info *fi, fuse_readdir_flags gflags) noexcept
		{
			BOOST_OUTCOME_TRY(auto fd, open_rel(path.path.c_str(), O_RDONLY | O_DIRECTORY));
			raii_dir dir_fd(std::move(fd));
			if (!dir_fd)
				return error::failure_from_errno();
			while (auto entry = dir_fd.next_entry())
			{
				filler(buf, entry->d_name, nullptr, 0, fuse_fill_dir_flags(0));
			}
			return errno_or_success{-errno};
		}

		errno_or_nonnegative read(const existing_path &path, char *buf, size_t size, off_t offset, fuse_file_info *fi) noexcept
		{
			BOOST_OUTCOME_TRY(auto fd, open_rel(path.path.c_str(), O_RDONLY));
			auto bytes_read = [&]{
				if (offset)
					return ::pread(fd.fd, buf, size, offset);
				else
					return ::read(fd.fd, buf, size);
			}();
			return errno_or_nonnegative::from_errno(bytes_read);
		}

		errno_or_success create(const maybe_new_path &path, mode_t mode, fuse_file_info *fi) noexcept
		{
			static constexpr auto create_flags = O_CREAT | O_WRONLY | O_TRUNC;
			BOOST_OUTCOME_TRY(auto fd, open_rel(path.real_path.c_str(), create_flags, mode));
			if (path.folded_path)
			{
				path_maps[*path.folded_path] = path.real_path;
			}
			return outcome::success();
		}

		errno_or_success mkdir(const maybe_new_path &path, mode_t mode) noexcept
		{
			BOOST_OUTCOME_TRYV(mkdir_rel(path.real_path.c_str(), mode));
			if (path.folded_path)
			{
				path_maps[*path.folded_path] = path.real_path;
			}
			return outcome::success();
		}

		errno_or_success unlink(const maybe_new_path &path) noexcept
		{
			BOOST_OUTCOME_TRYV(unlink_rel(path.real_path.c_str(), 0));
			if (path.folded_path)
			{
				path_maps.erase(*path.folded_path);
			}
			return outcome::success();
		}

		errno_or_success rmdir(const maybe_new_path &path) noexcept
		{
			BOOST_OUTCOME_TRYV(unlink_rel(path.real_path.c_str(), AT_REMOVEDIR));
			if (path.folded_path)
			{
				path_maps.erase(*path.folded_path);
			}
			return outcome::success();
		}

		errno_or_success symlink(const maybe_new_path &path, const char *target) noexcept
		{
			BOOST_OUTCOME_TRYV(symlink_rel(path.real_path.c_str(), target));
			if (path.folded_path)
			{
				path_maps[*path.folded_path] = path.real_path;
			}
			return outcome::success();
		}

		errno_or_success readlink(const existing_path &path, char *buf, size_t len) noexcept
		{
			BOOST_OUTCOME_TRY(auto ret_len, readlink_rel(path.path.c_str(), buf, len - 1));
			buf[ret_len] = '\0';
			return outcome::success();
		}

		errno_or_nonnegative write(const existing_path &path, const char *buf, size_t size, off_t offset, fuse_file_info *fi) noexcept
		{
			BOOST_OUTCOME_TRY(auto fd, open_rel(path.path.c_str(), O_WRONLY));
			auto bytes_written = [&]{
				if (offset)
					return ::pwrite(fd.fd, buf, size, offset);
				else
					return ::write(fd.fd, buf, size);
			}();
			return errno_or_nonnegative::from_errno(bytes_written);
		}

		errno_or_success rename(const maybe_new_path &path_from, const char *path_to_c, unsigned int flags) noexcept
		{
			if (flags & ~(RENAME_EXCHANGE | RENAME_NOREPLACE))
				return errno_or_success{-EINVAL};
			BOOST_OUTCOME_TRY(auto path_to, to_maybe_new_path(path_to_c));
			BOOST_OUTCOME_TRYV(rename_rel(path_from.real_path.c_str(), path_to.real_path.c_str(), flags));
			if (!(flags & RENAME_EXCHANGE))
			{
				if (path_from.folded_path)
				{
					path_maps.erase(*path_from.folded_path);
				}
				if (path_to.folded_path)
				{
					path_maps[*path_to.folded_path] = path_to.real_path;
				}
			}
			return outcome::success();
		}
	};

	template<>
	errno_result<existing_path> data::convert<existing_path>(const char *path) const noexcept
	{
		return to_existing_path(path);
	}

	template<>
	errno_result<maybe_new_path> data::convert<maybe_new_path>(const char *path) const noexcept
	{
		return to_maybe_new_path(path);
	}

	int result_convert(error r) noexcept
	{
		return r.err;
	}

	int result_convert(const errno_or_success r) noexcept
	{
		return r.err;
	}

	int result_convert(const errno_or_nonnegative r) noexcept
	{
		return r.err;
	}

	template <auto FunctionPtr>
	struct wrapper;

	template <class Ret, class PathArg, class ...Args, Ret (data::*FunctionPtr)(PathArg, Args...)>
	struct wrapper<FunctionPtr>
	{
		static int wrapper_func(const char *path, Args ...args)
		{
			auto d = data::get();
			auto converted = d->convert<std::decay_t<PathArg>>(path);
			if (converted.has_error())
			{
				return result_convert(converted.assume_error());
			}
			auto ret = (d->*FunctionPtr)(converted.value(), args...);
			return result_convert(ret);
		}

		static constexpr decltype(&wrapper_func) get_wrapper_func()
		{
			return &wrapper_func;
		}
	};

	// The target path is the second argument, not the first, so swap them when calling the implementation
	int symlink_wrapper_func(const char *from, const char *to)
	{
		return wrapper<&data::symlink>::wrapper_func(to, from);
	}

	constexpr fuse_operations ops{
#define O(name) .name = wrapper<&data::name>::get_wrapper_func()
		O(getattr),
		O(readlink),
		O(mkdir),
		O(unlink),
		O(rmdir),
		.symlink = &symlink_wrapper_func,
		O(rename),
		O(read),
		O(write),
		O(readdir),
		O(create),
#undef O
	};
}

int main(int argc, char **argv)
{
	fuse_args args = FUSE_ARGS_INIT(argc, argv);

	config c;
	// TODO: options
	//fuse_opt_parse(...)

	struct fuse_cmdline_opts opts;
	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help || opts.show_version || !opts.mountpoint)
		// Use the default handler if we're not actually running the filesystem
		return fuse_main(argc, argv, &ops, nullptr);

	c.mount_dir = opts.mountpoint;

	auto data_ptr = std::make_unique<data>(c);

	auto fuse = fuse_new(&args, &ops, sizeof(ops), data_ptr.get());
	if (!fuse)
		return 3;

	int ret = 1;
	if (fuse_mount(fuse, opts.mountpoint) == 0)
	{
		if (fuse_daemonize(opts.foreground) == 0)
		{
			auto session = fuse_get_session(fuse);
			if (fuse_set_signal_handlers(session) == 0)
			{
				ret = fuse_loop(fuse);
				fuse_remove_signal_handlers(session);
			}
		}
		fuse_unmount(fuse);
	}
	fuse_destroy(fuse);
	return ret;
}
