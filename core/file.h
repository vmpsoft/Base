#pragma once

namespace base
{
	class storage : public std::vector<uint8_t>
	{
	public:
		template<typename T>
		void push(T value) { push((const uint8_t *)(&value), sizeof(T)); }
		void push(const uint8_t *data, size_t size) { insert(end(), data, data + size); }
	};

	class unicode_string : public std::wstring
	{
	};

	template<typename T>
	class list
	{
	public:
		template <typename Base>
		class _Iterator
		{
			friend list;
			_Iterator() = default;
			_Iterator(const Base &base) : base_(base) {}
		public:
			T &operator*() const { return *(*base_); }
			bool operator==(const _Iterator &rhs) const { return base_ == rhs.base_; }
			bool operator!=(const _Iterator &rhs) const { return !(*this == rhs); }
			_Iterator &operator++() { ++base_; return *this; }
			_Iterator &operator--() { --base_; return *this; }
			_Iterator operator++(int) { return base_++; }
			_Iterator operator--(int) { return base_--; }
		private:
			Base base_;
		};

		template <typename Base, typename D>
		class _CastIterator
		{
		public:
			_CastIterator(const Base &base) : base_(base) {}
			D &operator*() const { return static_cast<D&>(*base_); }
			bool operator == (const _CastIterator &rhs) const { return base_ == rhs.base_; }
			bool operator != (const _CastIterator &rhs) const { return !(*this == rhs); }
			_CastIterator &operator++() { ++base_; return *this; }
			_CastIterator operator++(int) { return base_++; }
		private:
			Base base_;
		};

		using container = std::vector<std::unique_ptr<T>>;
		using iterator = _Iterator<typename container::iterator>;
		using const_iterator = _Iterator<typename container::const_iterator>;

		template <typename... Args>
		T &add(Args&&... params) {
			auto item = std::make_unique<T>(std::forward<Args>(params)...);
			T &res = *item;
			items_.emplace_back(std::move(item));
			return res;
		}

		template <typename T, typename... Args>
		T &add(Args&&... params) {
			auto item = std::make_unique<T>(std::forward<Args>(params)...);
			T &res = *item;
			items_.emplace_back(std::move(item));
			return res;
		}

		void push(std::unique_ptr<T> item) {
			items_.emplace_back(std::move(item));
		}

		T &item(size_t index) const { return *items_[index]; }
		T &first() const { return *items_.front(); }
		T &last() const { return *items_.back(); }
		void pop() { items_.pop_back(); }
		void clear() { items_.clear(); }
		size_t size() const { return items_.size(); }
		iterator begin() { return items_.begin(); }
		iterator end() { return items_.end(); }
		const_iterator begin() const { return items_.begin(); }
		const_iterator end() const { return items_.end(); }
	protected:
		container items_;
	};

	class stream
	{
		std::fstream file_;
	public:
		static constexpr uint64_t error = (uint64_t)-1;

		void close()
		{
			file_.close();
		}

		bool open(const std::string &file_name)
		{
			close();

			file_.open(file_name.c_str(), std::fstream::in | std::fstream::binary);
			return file_.is_open();
		}

		uint64_t seek(uint64_t position)
		{
			file_.seekg(position);
			if (!file_.good())
				return error;
			return position;
		}

		uint64_t tell()
		{
			return file_.tellg();
		}

		uint64_t size()
		{
			auto pos = file_.tellg();
			file_.seekg(0, std::ios::end);
			uint64_t res = file_.tellg() - pos;
			file_.seekg(pos);
			return res;
		}

		template<typename T>
		T read()
		{
			T res{};
			file_.read((char *)&res, sizeof(res));
			return res;
		}

		size_t read(void *buffer, size_t size)
		{
			file_.read((char *)buffer, size);
			if (!file_.good())
				return 0;
			return size;
		}
	};

	enum class status
	{
		success,
		open_error,
		unknown_format,
		invalid_format,
		unsupported_cpu,
		unsupported_subsystem
	};

	enum class operand_size
	{
		byte,
		word,
		dword,
		qword
	};

	class file;
	class load_command_list;
	class segment_list;
	class import_list;
	class import;
	class map_symbol_list;
	class export_list;

	class architecture
	{
	public:
		architecture(file *owner, uint64_t offset, uint64_t size);
		architecture(file *owner, const architecture &src);
		uint64_t seek(uint64_t position) const;
		bool seek_address(uint64_t address) const;
		uint64_t tell() const;
		template <typename T> T read() const { T res{}; read(&res, sizeof(res)); return res; }
		size_t read(void *buffer, size_t size) const;
		std::string read_string() const;
		file *owner() const { return owner_; }
		uint64_t offset() const { return offset_; }
		uint64_t size() const { return size_; }
		map_symbol_list &map_symbols() const { return *map_symbol_list_; }
		virtual std::string name() const = 0;
		virtual load_command_list &commands() const = 0;
		virtual segment_list &segments() const = 0;
		virtual import_list &imports() const = 0;
		virtual export_list &exports() const = 0;
		virtual operand_size address_size() const = 0;
	private:
		file *owner_;
		uint64_t offset_;
		uint64_t size_;
		std::unique_ptr<map_symbol_list> map_symbol_list_;
	};

	class file : public list<architecture>
	{
	public:
		virtual std::string format() const = 0;
		void close();
		virtual status load() = 0;
		status open(const std::string &file_name);
		uint64_t seek(uint64_t position);
		uint64_t tell();
		uint64_t size();
		size_t read(void *buffer, size_t size);
		std::string file_name() const { return file_name_; }
	private:
		stream stream_;
		std::string file_name_;
	};

	class load_command
	{
	public:
		load_command(load_command_list *owner) : owner_(owner) {}
		virtual uint64_t address() const = 0;
		virtual uint32_t size() const = 0;
		virtual size_t type() const = 0;
		virtual std::string name() const;
		load_command_list *owner() const { return owner_; }
	private:
		load_command_list *owner_;
	};

	class load_command_list : public list<load_command>
	{
	public:
		load_command_list(architecture *owner) : owner_(owner) {}
		load_command *find_type(size_t type) const;
	private:
		architecture *owner_;
	};

	template <typename T>
	class load_command_list_t : public load_command_list
	{
	public:
		using base::load_command_list::load_command_list;
		using iterator = _CastIterator<list::iterator, T>;
		using const_iterator = _CastIterator<list::const_iterator, T>;
		iterator begin() { return list::begin(); }
		iterator end() { return list::end(); }
		const_iterator begin() const { return list::begin(); }
		const_iterator end() const { return list::end(); }
		T *find_type(size_t type) const { return static_cast<T *>(load_command_list::find_type(type)); }
	};

	union memory_type_t
	{
		uint16_t flags;
		struct {
			uint16_t read : 1;
			uint16_t write : 1;
			uint16_t execute : 1;
			uint16_t shared : 1;
			uint16_t not_cached : 1;
			uint16_t not_paged : 1;
			uint16_t discardable : 1;
			uint16_t mapped : 1;
		};
	};

	class segment
	{
	public:
		segment(segment_list *owner) : owner_(owner) {}
		virtual uint64_t address() const = 0;
		virtual uint64_t size() const = 0;
		virtual uint32_t physical_offset() const = 0;
		virtual uint32_t physical_size() const = 0;
		virtual std::string name() const = 0;
		virtual memory_type_t memory_type() const = 0;
	private:
		segment_list *owner_;
	};

	class segment_list : public list<segment>
	{
	public:
		segment_list(architecture *owner) : owner_(owner) {}
		base::segment *find_mapped(uint64_t address) const;
	private:
		architecture *owner_;
	};

	template <typename T>
	class segment_list_t : public segment_list
	{
	public:
		using base::segment_list::segment_list;
		using iterator = _CastIterator<list::iterator, T>;
		using const_iterator = _CastIterator<list::const_iterator, T>;
		iterator begin() { return list::begin(); }
		iterator end() { return list::end(); }
		const_iterator begin() const { return list::begin(); }
		const_iterator end() const { return list::end(); }
		template <typename... Args>
		T &add(Args&&... params) { return base::segment_list::add<T>(this, std::forward<Args>(params)...); }
	};

	class import_function
	{
	public:
		import_function(import *owner) : owner_(owner) {}
		virtual std::string name() const = 0;
		virtual uint64_t address() const = 0;
	private:
		import *owner_;
	};

	class import : public list<import_function>
	{
	public:
		import(import_list *owner) : owner_(owner) {}
		virtual std::string name() const = 0;
	private:
		import_list *owner_;
	};

	class import_list : public list<import>
	{
	public:
		import_list(architecture *owner) : owner_(owner) {}
		import *find_name(const std::string &name) const;
	private:
		architecture *owner_;
	};

	class export_symbol
	{
	public:
		virtual uint64_t address() const = 0;
		virtual std::string name() const = 0;
	};

	class export_list : public base::list<export_symbol>
	{

	};

	enum class symbol_type_id
	{
		function,
		data
	};

	class map_symbol
	{
	public:
		map_symbol(uint64_t address, const std::string &name, symbol_type_id type);
		map_symbol(const map_symbol &src);
		std::unique_ptr<map_symbol> clone() const;
		uint64_t address() const { return address_; }
		std::string name() const { return name_; }
		symbol_type_id type() const { return type_; }
	private:
		uint64_t address_;
		std::string name_;
		symbol_type_id type_;
	};

	class map_symbol_list : public list<map_symbol>
	{
	public:
		map_symbol_list() = default;
		map_symbol_list(const map_symbol_list &src);
		std::unique_ptr<map_symbol_list> clone() const;
	};

	class format
	{
	public:
		virtual bool check(base::stream &stream) const = 0;
		virtual std::unique_ptr<file> instance() const = 0;
	};
}