#pragma once

#include "file.h"
#include "pe.h"

namespace net
{
	std::string symbol_name(const std::string &ret, const std::string &type, const std::string &method, const std::string &signature);

#pragma pack(push, 1)
	class format
	{
	public:
		using data_directory_t = pe::format::data_directory_t;
		using version_t = pe::format::version_t;
		using ex_version_t = pe::format::ex_version_t;

		struct cor20_header_t
		{
			uint32_t            size;
			ex_version_t        runtime_version;
			data_directory_t    meta_data;
			uint32_t            flags;
			union {
				uint32_t        entry_point_token;
				uint32_t        entry_point_rva;
			};
			data_directory_t    resources;
			data_directory_t    strong_name_signature;
			data_directory_t    code_manager_table;
			data_directory_t    vtable_fixups;
			data_directory_t    export_address_table_jumps;
			data_directory_t    managed_native_header;
		};

		static constexpr uint32_t meta_data_signature = 'BJSB';

		struct meta_data_header_t
		{
			uint32_t           signature;
			ex_version_t       version;
			uint32_t           reserved;
			uint32_t           version_size;
		};

		struct stream_header_t
		{
			uint32_t           offset;
			uint32_t           size;
		};


		union heap_offset_sizes_t
		{
			uint8_t            value;
			struct
			{
				uint8_t        string_field_size : 1;
				uint8_t        guid_field_size : 1;
				uint8_t        blob_field_size : 1;
				uint8_t        reserved : 5;
			};
		};

		struct heap_header_t
		{
			uint32_t            reserved;
			version_t           version;
			heap_offset_sizes_t heap_offset_sizes;
			uint8_t             reserved2;
			uint64_t            mask_valid;
			uint64_t            mask_sorted;
		};

		union type_attributes_t
		{
			uint32_t         flags;
			struct
			{
				uint32_t      visibility : 3;
				uint32_t      sequential_layout : 1;
				uint32_t      explicit_layout : 1;
				uint32_t      interface : 1;
				uint32_t      reserved : 1;
				uint32_t      abstract : 1;

				uint32_t      sealed : 1;
				uint32_t      reserved2 : 1;
				uint32_t      special_name : 1;
			};
		};

		union field_attributes_t
		{
			uint16_t         flags;
		};

		union method_attributes_t
		{
			uint16_t         flags;
		};

		union method_impl_t
		{
			uint16_t         flags;
		};

		enum element_type_id : uint8_t
		{
			end = 0x0,
			_void = 0x1,
			boolean = 0x2,
			_char = 0x3,
			i1 = 0x4,
			u1 = 0x5,
			i2 = 0x6,
			u2 = 0x7,
			i4 = 0x8,
			u4 = 0x9,
			i8 = 0xa,
			u8 = 0xb,
			r4 = 0xc,
			r8 = 0xd,
			string = 0xe,
			ptr = 0xf,
			byref = 0x10,
			valuetype = 0x11,
			_class = 0x12,
			var = 0x13,
			array = 0x14,
			genericinst = 0x15,
			typedbyref= 0x16,
			i = 0x18,
			u = 0x19,
			fnptr = 0x1B,
			object = 0x1C,
			szarray = 0x1D,
			mvar = 0x1E,
			cmod_reqd = 0x1f,
			cmod_opt = 0x20,
			internal = 0x21,
			modifier = 0x40,
			sentinel = 0x01 | modifier,
			pinned = 0x05 | modifier,
			type = 0x50,
			tagged_object = 0x51,
			_enum = 0x55
		};
	};
#pragma pack(pop)

	class storage : public base::storage
	{
	public:
		storage() = default;
		storage(const uint8_t *data, size_t size);
	};

	class storage_view
	{
	public:
		storage_view(const storage &storage, size_t position = 0);
		uint32_t read_encoded();
		std::string read_string();
		size_t tell() const { return position_; }
		void seek(size_t position) { position_ = position; }
		template<typename T> T read() { T res{}; read(&res, sizeof(res)); return res; }
	private:
		void read(void *buffer, size_t size);
		const uint8_t *data_;
		size_t size_;
		size_t position_;
	};

	enum class token_type_id : uint32_t
	{
		module = 0x00,
		type_ref = 0x01,
		type_def = 0x02,
		field = 0x04,
		method_def = 0x06,
		param = 0x08,
		interface_impl = 0x09,
		member_ref = 0x0a,
		constant = 0x0b,
		custom_attribute = 0x0c,
		field_marshal = 0x0d,
		decl_security = 0x0e,
		class_layout = 0x0f,
		field_layout = 0x10,
		stand_alone_sig = 0x11,
		event_map = 0x12,
		event = 0x14,
		property_map = 0x15,
		property = 0x17,
		method_semantics = 0x18,
		method_impl = 0x19,
		module_ref = 0x1a,
		type_spec = 0x1b,
		impl_map = 0x1c,
		field_rva = 0x1d,
		enc_log = 0x1e,
		enc_map = 0x1f,
		assembly = 0x20,
		assembly_processor = 0x21,
		assembly_os = 0x22,
		assembly_ref = 0x23,
		assembly_ref_processor = 0x24,
		assembly_ref_os = 0x25,
		file = 0x26,
		exported_type = 0x27,
		manifest_resource = 0x28,
		nested_class = 0x29,
		generic_param = 0x2a,
		method_spec = 0x2b,
		generic_param_constraint = 0x2c,
		invalid = 0xff
	};

	class architecture;
	class meta_data;
	class table;

	union token_value_t 
	{
		uint32_t id;
		struct
		{
			uint32_t value : 24;
			token_type_id type : 8;
		};
		token_value_t() = default;
		token_value_t(token_type_id type_, uint32_t value_) : type(type_), value(value_) {}
		token_value_t(uint32_t id_) : id(id) {}
	};

	struct token_encoding_t
	{
		token_type_id types[22];
		uint8_t size;
		uint8_t bits;

		template<typename... Args>
		static constexpr token_encoding_t construct(uint8_t bits, Args... args) {
			return { {args...}, sizeof...(Args), bits };
		}
	};

	static constexpr token_encoding_t resolution_scope_encoding = token_encoding_t::construct(2,
		token_type_id::module, token_type_id::module_ref, token_type_id::assembly_ref, token_type_id::type_ref);

	static constexpr token_encoding_t type_def_ref_encoding = token_encoding_t::construct(2,
		token_type_id::type_def, token_type_id::type_ref, token_type_id::type_spec);

	static constexpr token_encoding_t member_ref_parent_encoding = token_encoding_t::construct(3,
		token_type_id::type_def, token_type_id::type_ref, token_type_id::module_ref, token_type_id::method_def, token_type_id::type_spec);

	static constexpr token_encoding_t has_constant_encoding = token_encoding_t::construct(2,
		token_type_id::field, token_type_id::param, token_type_id::property);

	static constexpr token_encoding_t has_custom_attribute_encoding = token_encoding_t::construct(5,
		token_type_id::method_def, token_type_id::field, token_type_id::type_ref, token_type_id::type_def, token_type_id::param, token_type_id::interface_impl, token_type_id::member_ref,
		token_type_id::module, token_type_id::decl_security, token_type_id::property, token_type_id::event, token_type_id::stand_alone_sig, token_type_id::module_ref, token_type_id::type_spec,
		token_type_id::assembly, token_type_id::assembly_ref, token_type_id::file, token_type_id::exported_type, token_type_id::manifest_resource, token_type_id::generic_param,
		token_type_id::generic_param_constraint, token_type_id::method_spec);

	static constexpr token_encoding_t custom_attribute_encoding = token_encoding_t::construct(3,
		token_type_id::invalid, token_type_id::invalid, token_type_id::method_def, token_type_id::member_ref);

	static constexpr token_encoding_t has_field_marshal_encoding = token_encoding_t::construct(1,
		token_type_id::field, token_type_id::param);

	static constexpr token_encoding_t has_decl_security_encoding = token_encoding_t::construct(2,
		token_type_id::type_def, token_type_id::method_def, token_type_id::assembly);

	static constexpr token_encoding_t has_semantics_encoding = token_encoding_t::construct(1,
		token_type_id::event, token_type_id::property);

	static constexpr token_encoding_t method_def_ref_encoding = token_encoding_t::construct(1,
		token_type_id::method_def, token_type_id::member_ref);

	static constexpr token_encoding_t member_forwarded_encoding = token_encoding_t::construct(1,
		token_type_id::field, token_type_id::method_def);

	static constexpr token_encoding_t implementation_encoding = token_encoding_t::construct(2,
		token_type_id::file, token_type_id::assembly_ref, token_type_id::exported_type);

	static constexpr token_encoding_t type_or_methoddef_encoding = token_encoding_t::construct(1,
		token_type_id::type_def, token_type_id::method_def);

	class token
	{
	public:
		token(meta_data *owner, token_value_t value);
		virtual void load(architecture &file) {}
		uint32_t id() const { return value_.id; }
		token_type_id type() const { return value_.type; }
		token *next() const;
	protected:
		std::string read_string(architecture &file) const;
		std::string read_user_string(uint32_t value) const;
		storage read_blob(architecture &file) const;
		storage read_guid(architecture &file) const;
		token *read_token(architecture &file, const token_encoding_t &encoding) const;
		token *read_token(architecture &file, token_type_id type) const;
	private:
		meta_data *meta_;
		token_value_t value_;
	};

	class module : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t generation_;
		std::string name_;
		storage mv_id_;
		storage enc_id_;
		storage enc_base_id_;
	};

	class type_ref : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
		type_ref *declaring_type() const;
		std::string full_name() const;
		token *resolution_scope() const { return resolution_scope_; }
	private:
		token *resolution_scope_;
		std::string name_;
		std::string namespace_;
	};

	class field;
	class method_def;
	class param;
	class event;
	class property;
	class signature;

	class type_def : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
		std::string full_name() const;
		std::string name() const { return name_; }
		method_def *method_list() const { return method_list_; }
		type_def *next() const { return static_cast<type_def *>(token::next()); }
	private:
		format::type_attributes_t flags_;
		std::string name_;
		std::string namespace_;
		token *base_type_;
		field *field_list_;
		method_def *method_list_;
		type_def *declaring_type_;
		uint32_t class_size_;
	};

	class array_shape
	{
	public:
		void load(storage_view &data);
		std::string name() const;
	private:
		uint32_t rank_;
		std::vector<uint32_t> sizes_;
		std::vector<uint32_t> lo_bounds_;
	};

	class generic_arguments;

	class element
	{
	public:
		element(meta_data *owner) : owner_(owner) {}
		void load(const storage &data);
		void load(storage_view &data);
		format::element_type_id type() const { return type_; }
		std::string name(generic_arguments *args = nullptr) const;
		uint32_t number() const { return generic_param_; }
		element *next() const { return next_.get(); }
		token *token() const { return token_; }
		void push_args(generic_arguments &args, bool is_type) const;
	private:
		void read_type(storage_view &data);

		meta_data *owner_;
		format::element_type_id type_;
		bool byref_;
		bool pinned_;
		bool sentinel_;
		uint32_t generic_param_;
		std::unique_ptr<element> next_;
		net::token *token_;
		std::unique_ptr<signature> method_;
		std::unique_ptr<array_shape> array_shape_;
		base::list<element> mod_list_;
		base::list<element> child_list_;
	};

	class generic_arguments
	{
	public:
		generic_arguments(generic_arguments *src = nullptr);
		void clear();
		void push_arg(element *arg, bool is_type);
		element *resolve(const element &type) const;
		element *method_arg(size_t index) const { return (index < method_args_.size()) ? method_args_[index] : nullptr; }
	private:
		std::vector<element *> method_args_;
		std::vector<element *> type_args_;
	};

	enum class signature_type_id : uint8_t
	{
		def,
		c_call,
		std_call,
		this_call,
		fast_call,
		var_arg,
		field,
		local,
		property,
		unmanaged,
		generic_inst,
		native_var_arg,
	};

	union signature_type_t
	{
		uint8_t value;
		struct {
			signature_type_id type : 4;
			uint8_t           generic : 1;
			uint8_t           has_this : 1;
			uint8_t           explicit_this : 1;
			uint8_t           reserved : 1;
		};

		bool is_method() const
		{
			switch (type) {
			case signature_type_id::def:
			case signature_type_id::c_call:
			case signature_type_id::std_call:
			case signature_type_id::this_call:
			case signature_type_id::fast_call:
			case signature_type_id::var_arg:
			case signature_type_id::unmanaged:
			case signature_type_id::native_var_arg:
				return true;
			}
			return false;
		}
	};

	class signature: public base::list<element>
	{
	public:
		signature(meta_data *owner);
		void load(const storage &storage);
		void load(storage_view &storage);
		std::string ret_name(generic_arguments *args = nullptr) const;
		std::string name(generic_arguments *args = nullptr) const;
		signature_type_t type() const { return type_; };
		void push_args(generic_arguments &args, bool is_type) const;
	private:
		meta_data *owner_;
		signature_type_t type_;
		uint32_t gen_param_count_;
		std::unique_ptr<element> ret_;
	};

	class field : public token
	{
	public:
		field(meta_data *owner, token_value_t value);
		virtual void load(architecture &file);
	private:
		format::field_attributes_t flags_;
		std::string name_;
		std::unique_ptr<signature> signature_;
		type_def *declaring_type_;
	};

	class method_def : public token
	{
	public:
		method_def(meta_data *owner, token_value_t value);
		virtual void load(architecture &file);
		std::string full_name(generic_arguments *args = nullptr) const;
		type_def *declaring_type() const { return declaring_type_; }
		void set_declaring_type(type_def *type) { declaring_type_ = type; }
		uint64_t address() const { return address_; }
		method_def *next() const { return static_cast<method_def *>(token::next()); }
	private:
		std::unique_ptr<signature> signature_;
		uint64_t address_;
		format::method_impl_t impl_;
		format::method_attributes_t flags_;
		std::string name_;
		param *param_list_;
		type_def *declaring_type_;
	};

	class param : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t flags_;
		uint16_t sequence_;
		std::string name_;
	};

	class interface_impl : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		type_def *class_;
		token *interface_;
	};

	class member_ref : public token
	{
	public:
		member_ref(meta_data *owner, token_value_t value);
		virtual void load(architecture &file);
		std::string full_name(generic_arguments *args = nullptr) const;
		token *declaring_type() const { return declaring_type_; }
	private:
		std::unique_ptr<signature> signature_;
		token *declaring_type_;
		std::string name_;
	};

	class constant : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint8_t type_;
		uint8_t padding_zero_;
		token *parent_;
		storage value_;
	};

	class custom_attribute : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		token *parent_;
		token *type_;
		storage value_;
	};

	class field_marshal : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		token *parent_;
		storage native_type_;
	};

	class decl_security : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t action_;
		token *parent_;
		storage permission_set_;
	};

	class class_layout : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t packing_size_;
		uint32_t class_size_;
		type_def *parent_;
	};

	class field_layout : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t offset_;
		field *field_;
	};

	class stand_alone_sig : public token
	{
	public:
		stand_alone_sig(meta_data *owner, token_value_t value);
		virtual void load(architecture &file);
	private:
		std::unique_ptr<signature> signature_;
	};

	class event_map : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		type_def *parent_;
		event *event_list_;
	};

	class event : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t flags_;
		std::string name_;
		token *parent_;
	};

	class property_map : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		type_def *parent_;
		property *property_list_;
	};

	class property : public token
	{
	public:
		property(meta_data *owner, token_value_t value);
		virtual void load(architecture &file);
	private:
		uint16_t flags_;
		std::string name_;
		std::unique_ptr<signature> signature_;
	};

	class method_semantics : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t flags_;
		method_def *method_;
		token *association_;
	};

	class method_impl : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		type_def *class_;
		token *body_;
		token *declaration_;
	};

	class module_ref : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
		std::string name() const { return name_; }
	private:
		std::string name_;
	};

	class type_spec : public token
	{
	public:
		type_spec(meta_data *owner, token_value_t value);
		std::string name() const { return signature_->name(); }
		element *signature() const { return signature_.get(); }
		virtual void load(architecture &file);
	private:
		std::unique_ptr<element> signature_;
	};

	class impl_map : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
		module_ref *import_scope() const { return import_scope_; }
		std::string import_name() const { return import_name_; }
	private:
		uint16_t mapping_flags_;
		token *member_forwarded_;
		std::string import_name_;
		module_ref *import_scope_;
	};

	class field_rva : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint64_t address_;
		field *field_;
	};

	class enc_log : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t token_;
		uint32_t func_code_;
	};

	class enc_map : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t token_;
	};

	class assembly : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t hash_id_;
		format::ex_version_t version_;
		uint16_t minor_version_;
		uint16_t build_number_;
		uint16_t revision_number_;
		uint32_t flags_;
		storage public_key_;
		std::string name_;
		std::string culture_;
	};

	class assembly_processor : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t processor_;
	};

	class assembly_os : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t os_platform_id_;
		uint32_t os_major_version_;
		uint32_t os_minor_version_;
	};

	class assembly_ref : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
		std::string name() const { return name_; }
	private:
		format::ex_version_t version_;
		uint16_t build_number_;
		uint16_t revision_number_;
		uint32_t flags_;
		storage public_key_or_token_;
		std::string name_;
		std::string culture_;
		storage hash_value_;
	};

	class assembly_ref_processor : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t processor_;
		assembly_ref *assembly_ref_;
	};

	class assembly_ref_os : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t os_platform_id_;
		uint32_t os_major_version_;
		uint32_t os_minor_version_;
		assembly_ref *assembly_ref_;
	};

	class tfile : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t flags_;
		std::string name_;
		storage value_;
	};

	class exported_type : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t flags_;
		uint32_t type_def_id_;
		std::string name_;
		std::string namespace_;
		token *implementation_;
	};

	class manifest_resource : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint32_t offset_;
		uint32_t flags_;
		std::string name_;
		token *implementation_;
	};

	class nested_class : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		type_def *nested_type_;
		type_def *declaring_type_;
	};

	class generic_param : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		uint16_t number_;
		uint16_t flags_;
		token *parent_;
		std::string name_;
	};

	class method_spec : public token
	{
	public:
		method_spec(meta_data *owner, token_value_t value);
		virtual void load(architecture &file);
		std::string full_name() const;
	private:
		token *parent_;
		std::unique_ptr<signature> signature_;
	};

	class generic_param_constraint : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		generic_param *parent_;
		token *constraint_;
	};

	class table : public base::list<token>
	{
	public:
		table(meta_data *owner, token_type_id type, uint32_t token_count);
		void load(architecture &file);
		token_type_id type() const { return type_; }
	private:
		meta_data *owner_;
		token_type_id type_;
	};

	class stream : public base::load_command
	{
	public:
		stream(meta_data *owner, uint64_t address, uint32_t size, const std::string &name);
		meta_data *owner() const;
		virtual uint64_t address() const { return address_; }
		virtual uint32_t size() const { return size_; }
		virtual size_t type() const { return 0; }
		virtual std::string name() const { return name_; }
		virtual void load(architecture &file) {}
	private:
		uint64_t address_;
		uint32_t size_;
		std::string name_;
	};

	class heap_stream : public stream
	{
	public:
		using stream::stream;
		virtual void load(architecture &file);
		const base::list<table> &table_list() const { return table_list_; }
		format::heap_offset_sizes_t offset_sizes() const { return offset_sizes_; }
	private:
		format::heap_offset_sizes_t offset_sizes_;
		base::list<table> table_list_;
	};

	class strings_stream : public stream
	{
	public:
		using stream::stream;
		virtual void load(architecture &file);
		std::string resolve(uint32_t offset) const;
	private:
		storage data_;
	};

	class user_strings_stream : public stream
	{
	public:
		using stream::stream;
		virtual void load(architecture &file);
		std::string resolve(uint32_t offset) const;
	private:
		storage data_;
	};

	class guid_stream : public stream
	{
	public:
		using stream::stream;
		virtual void load(architecture &file);
		storage resolve(uint32_t offset);
	private:
		storage data_;
	};

	class blob_stream : public stream
	{
	public:
		blob_stream(meta_data *owner, uint64_t address, uint32_t size, const std::string &name);
		virtual void load(architecture &file);
		storage resolve(uint32_t offset) const;
	private:
		storage data_;
	};

	class meta_data : public base::load_command_list
	{
		using iterator = _CastIterator<list::iterator, stream>;
		using const_iterator = _CastIterator<list::const_iterator, const stream>;
		iterator begin() { return list::begin(); }
		iterator end() { return list::end(); }
		const_iterator begin() const { return list::begin(); }
		const_iterator end() const { return list::end(); }
	public:
		using load_command_list::load_command_list;
		template <typename T, typename... Args>
		T &add(Args&&... params) { return base::load_command_list::add<T>(this, std::forward<Args>(params)...); }
		void load(architecture &file, uint64_t address);
		table *table(token_type_id type) const;
		std::string user_string(uint32_t offset) const;
		std::string string(uint32_t offset) const;
		storage guid(uint32_t offset) const;
		storage blob(uint32_t offset) const;
		token *find(token_value_t id) const;
		bool string_field_size() const { return heap_->offset_sizes().string_field_size; }
		bool guid_field_size() const { return heap_->offset_sizes().guid_field_size; }
		bool blob_field_size() const { return heap_->offset_sizes().blob_field_size; }
		bool field_size(const token_encoding_t &encoding) const;
		bool field_size(token_type_id type) const;
	private:
		std::string version_;
		heap_stream *heap_ = nullptr;
		strings_stream *strings_ = nullptr;
		user_strings_stream *user_strings_ = nullptr;
		guid_stream *guid_ = nullptr;
		blob_stream *blob_ = nullptr;
	};

	class import_list;
	class import;

	class import_function : public base::import_function
	{
	public:
		import_function(import *owner, uint32_t token, const std::string &name);
		virtual std::string name() const { return name_; }
		virtual uint64_t address() const { return token_; }
	private:
		uint32_t token_;
		std::string name_;
	};

	class import : public base::import
	{
	public:
		import(import_list *owner, const std::string &name);
		template <typename... Args>
		import_function & add(Args&&... params) { return base::import::add<import_function>(this, std::forward<Args>(params)...); }
		virtual std::string name() const { return name_; }
	private:
		std::string name_;
	};

	class import_list : public base::import_list
	{
	public:
		using base::import_list::import_list;
		void load(architecture &file);
		template <typename... Args>
		import &add(Args&&... params) { return base::import_list::add<import>(this, std::forward<Args>(params)...); }
		import *find_name(const std::string &name) const { return static_cast<import *>(base::import_list::find_name(name)); }
	};

	class symbol_list : public base::symbol_list
	{
	public:
		void load(architecture &file);
	};

	using segment = pe::segment;
	using segment_list = pe::segment_list;

	class architecture : public base::architecture
	{
	public:
		architecture(pe::architecture &file);
		virtual std::string name() const { return ".NET"; }
		base::status load();
		uint64_t image_base() const { return file_.image_base(); }
		virtual base::operand_size address_size() const { return file_.address_size(); }
		virtual meta_data *commands() const { return meta_data_.get(); }
		virtual segment_list *segments() const { return file_.segments(); }
		virtual import_list *imports() const { return import_list_.get(); }
		virtual symbol_list *symbols() const { return symbol_list_.get(); }
		virtual base::export_list *exports() const { return nullptr; }
	private:
		pe::architecture &file_;
		std::unique_ptr<meta_data> meta_data_;
		std::unique_ptr<import_list> import_list_;
		std::unique_ptr<symbol_list> symbol_list_;
	};
}
