#pragma once

#include "file.h"
#include "pe.h"

namespace net
{
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

	};
#pragma pack(pop)

	class storage : public base::storage
	{
	public:
		storage() : base::storage() {}
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
	private:
		void read(void *buffer, size_t size);
		template<typename T> T read() { T res{}; read(&res, sizeof(res)); return res; }
		const uint8_t *data_;
		size_t size_;
		size_t position_;
	};

	enum class token_type_id : uint8_t
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
		generic_param_constraint = 0x2c
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
	};

	struct token_encoding_t
	{
		token_type_id types[20];
		uint8_t size;
		uint8_t bits;
	};

	static constexpr token_encoding_t resolution_scope_encoding = { {token_type_id::module, token_type_id::module_ref, token_type_id::assembly_ref, token_type_id::type_ref}, 4, 2 };
	static constexpr token_encoding_t type_def_ref_encoding = { {token_type_id::type_def, token_type_id::type_ref, token_type_id::type_spec}, 3, 2 };

	/*

	const EncodingDesc TypeDefRef = EncodingDesc(typedef_ref_types, _countof(typedef_ref_types), 2);
	const EncodingDesc TypeMethodDef = EncodingDesc(type_or_methoddef_types, _countof(type_or_methoddef_types), 1);
	const EncodingDesc HasSemantics = EncodingDesc(has_semantics_types, _countof(has_semantics_types), 1);
	const EncodingDesc MethodDefRef = EncodingDesc(methoddef_ref_types, _countof(methoddef_ref_types), 1);
	const EncodingDesc MemberForwarded = EncodingDesc(member_forwarded_types, _countof(member_forwarded_types), 1);
	const EncodingDesc HasFieldMarshal = EncodingDesc(has_field_marshal_types, _countof(has_field_marshal_types), 1);
	const EncodingDesc Implementation = EncodingDesc(implementation_types, _countof(implementation_types), 2);
	const EncodingDesc MemberRefParent = EncodingDesc(member_ref_parent_types, _countof(member_ref_parent_types), 3);
	const EncodingDesc HasConstant = EncodingDesc(has_constant_types, _countof(has_constant_types), 2);
	const EncodingDesc CustomAttribute = EncodingDesc(custom_attribute_types, _countof(custom_attribute_types), 3);
	const EncodingDesc HasCustomAttribute = EncodingDesc(has_custom_attribute_types, _countof(has_custom_attribute_types), 5);
	const EncodingDesc HasDeclSecurity = EncodingDesc(has_decl_security_types, _countof(has_decl_security_types), 2);

	*/




	class token
	{
	public:
		token(meta_data *owner, token_value_t id);
		virtual void load(architecture &file) {}
	protected:
		token_value_t id() const { return id_; }
		std::string read_string(architecture &file) const;
		std::string read_user_string(uint32_t value) const;
		storage read_blob(architecture &file) const;
		storage read_guid(architecture &file) const;
		token *read_token(architecture &file, const token_encoding_t &encoding) const;
		token *read_token(architecture &file, token_type_id type) const;
	private:
		meta_data *meta_;
		token_value_t id_;
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
	private:
		token *resolution_scope_;
		std::string name_;
		std::string namespace_;
	};

	class field;
	class method_def;
	class param;

	class type_def : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
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

	class signature
	{
	public:
		void load(const storage &storage) {}
	};

	class field : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		format::field_attributes_t flags_;
		std::string name_;
		std::unique_ptr<signature> signature_ = std::make_unique<signature>();
		type_def *declaring_type_;
	};

	class method_def : public token
	{
	public:
		using token::token;
		virtual void load(architecture &file);
	private:
		std::unique_ptr<signature> signature_ = std::make_unique<signature>();
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
		param(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class interface_impl : public token
	{
	public:
		interface_impl(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class member_ref : public token
	{
	public:
		member_ref(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class constant : public token
	{
	public:
		constant(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class custom_attribute : public token
	{
	public:
		custom_attribute(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class field_marshal : public token
	{
	public:
		field_marshal(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class decl_security : public token
	{
	public:
		decl_security(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class class_layout : public token
	{
	public:
		class_layout(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class field_layout : public token
	{
	public:
		field_layout(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class stand_alone_sig : public token
	{
	public:
		stand_alone_sig(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class event_map : public token
	{
	public:
		event_map(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class event : public token
	{
	public:
		event(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class property_map : public token
	{
	public:
		property_map(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class property : public token
	{
	public:
		property(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class method_semantics : public token
	{
	public:
		method_semantics(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class method_impl : public token
	{
	public:
		method_impl(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class module_ref : public token
	{
	public:
		module_ref(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class type_spec : public token
	{
	public:
		type_spec(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class impl_map : public token
	{
	public:
		impl_map(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class field_rva : public token
	{
	public:
		field_rva(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class enc_log : public token
	{
	public:
		enc_log(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class enc_map : public token
	{
	public:
		enc_map(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class assembly : public token
	{
	public:
		assembly(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class assembly_processor : public token
	{
	public:
		assembly_processor(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class assembly_os : public token
	{
	public:
		assembly_os(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class assembly_ref : public token
	{
	public:
		assembly_ref(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class assembly_ref_processor : public token
	{
	public:
		assembly_ref_processor(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class assembly_ref_os : public token
	{
	public:
		assembly_ref_os(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class file_token : public token
	{
	public:
		file_token(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class exported_type : public token
	{
	public:
		exported_type(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class manifest_resource : public token
	{
	public:
		manifest_resource(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class nested_class : public token
	{
	public:
		nested_class(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class generic_param : public token
	{
	public:
		generic_param(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class method_spec : public token
	{
	public:
		method_spec(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
	};

	class generic_param_constraint : public token
	{
	public:
		generic_param_constraint(table *owner, token_value_t value);
		virtual void load(architecture &file) {}
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

	class meta_data : public base::load_command_list_t<stream>
	{
	public:
		using load_command_list_t::load_command_list_t;
		void load(architecture &file, uint64_t address);
		table *table(token_type_id type) const;
		std::string user_string(uint32_t offset) const;
		std::string string(uint32_t offset) const;
		storage guid(uint32_t offset) const;
		storage blob(uint32_t offset) const;
		token *token(token_value_t id) const;
		bool string_field_size() const { return heap_->offset_sizes().string_field_size; }
		bool guid_field_size() const { return heap_->offset_sizes().guid_field_size; }
		bool blob_field_size() const { return heap_->offset_sizes().blob_field_size; }
		bool field_size(const token_encoding_t &encoding) const;
		bool field_size(token_type_id type) const;
	private:
		uint32_t token_count(token_type_id type) const;
		std::string version_;
		heap_stream *heap_ = nullptr;
		strings_stream *strings_ = nullptr;
		user_strings_stream *user_strings_ = nullptr;
		guid_stream *guid_ = nullptr;
		blob_stream *blob_ = nullptr;
	};

	class architecture : public base::architecture
	{
	public:
		architecture(pe::architecture &file);
		virtual std::string name() const { return ".NET"; }
		base::status load();
		uint64_t image_base() const { return file_.image_base(); }
		virtual meta_data *command_list() const { return meta_data_.get(); }
		virtual pe::segment_list *segment_list() const { return file_.segment_list(); }
		virtual base::import_list *import_list() const { return nullptr; }
		virtual base::operand_size address_size() const { return file_.address_size(); }
	private:
		pe::architecture &file_;
		std::unique_ptr<meta_data> meta_data_;
	};
}
