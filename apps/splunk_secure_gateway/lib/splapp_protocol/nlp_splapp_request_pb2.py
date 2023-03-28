# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: nlp_splapp_request.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='nlp_splapp_request.proto',
  package='Application',
  syntax='proto3',
  serialized_options=_b('\n\036com.splunk.nlp.spacebridge.appP\001'),
  serialized_pb=_b('\n\x18nlp_splapp_request.proto\x12\x0b\x41pplication\"1\n\x18SavedSearchSPLGetRequest\x12\x15\n\rsavedSearchId\x18\x01 \x01(\t\"(\n\x19SavedSearchSPLGetResponse\x12\x0b\n\x03spl\x18\x01 \x01(\t\"/\n\x13SavedSearchMetaData\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\"3\n\x18SavedSearchesSyncRequest\x12\x17\n\x0fifModifiedSince\x18\x01 \x01(\x03\"\\\n\x19SavedSearchesSyncResponse\x12?\n\x15savedSearchesMetaData\x18\x01 \x03(\x0b\x32 .Application.SavedSearchMetaData\"-\n\x11\x44\x61shboardMetaData\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\"0\n\x15\x44\x61shboardsSyncRequest\x12\x17\n\x0fifModifiedSince\x18\x01 \x01(\x03\"T\n\x16\x44\x61shboardsSyncResponse\x12:\n\x12\x64\x61shboardsMetaData\x18\x01 \x03(\x0b\x32\x1e.Application.DashboardMetaDataB\"\n\x1e\x63om.splunk.nlp.spacebridge.appP\x01\x62\x06proto3')
)




_SAVEDSEARCHSPLGETREQUEST = _descriptor.Descriptor(
  name='SavedSearchSPLGetRequest',
  full_name='Application.SavedSearchSPLGetRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='savedSearchId', full_name='Application.SavedSearchSPLGetRequest.savedSearchId', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=41,
  serialized_end=90,
)


_SAVEDSEARCHSPLGETRESPONSE = _descriptor.Descriptor(
  name='SavedSearchSPLGetResponse',
  full_name='Application.SavedSearchSPLGetResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='spl', full_name='Application.SavedSearchSPLGetResponse.spl', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=92,
  serialized_end=132,
)


_SAVEDSEARCHMETADATA = _descriptor.Descriptor(
  name='SavedSearchMetaData',
  full_name='Application.SavedSearchMetaData',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='Application.SavedSearchMetaData.id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='name', full_name='Application.SavedSearchMetaData.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=134,
  serialized_end=181,
)


_SAVEDSEARCHESSYNCREQUEST = _descriptor.Descriptor(
  name='SavedSearchesSyncRequest',
  full_name='Application.SavedSearchesSyncRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ifModifiedSince', full_name='Application.SavedSearchesSyncRequest.ifModifiedSince', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=183,
  serialized_end=234,
)


_SAVEDSEARCHESSYNCRESPONSE = _descriptor.Descriptor(
  name='SavedSearchesSyncResponse',
  full_name='Application.SavedSearchesSyncResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='savedSearchesMetaData', full_name='Application.SavedSearchesSyncResponse.savedSearchesMetaData', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=236,
  serialized_end=328,
)


_DASHBOARDMETADATA = _descriptor.Descriptor(
  name='DashboardMetaData',
  full_name='Application.DashboardMetaData',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='Application.DashboardMetaData.id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='name', full_name='Application.DashboardMetaData.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=330,
  serialized_end=375,
)


_DASHBOARDSSYNCREQUEST = _descriptor.Descriptor(
  name='DashboardsSyncRequest',
  full_name='Application.DashboardsSyncRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ifModifiedSince', full_name='Application.DashboardsSyncRequest.ifModifiedSince', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=377,
  serialized_end=425,
)


_DASHBOARDSSYNCRESPONSE = _descriptor.Descriptor(
  name='DashboardsSyncResponse',
  full_name='Application.DashboardsSyncResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='dashboardsMetaData', full_name='Application.DashboardsSyncResponse.dashboardsMetaData', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=427,
  serialized_end=511,
)

_SAVEDSEARCHESSYNCRESPONSE.fields_by_name['savedSearchesMetaData'].message_type = _SAVEDSEARCHMETADATA
_DASHBOARDSSYNCRESPONSE.fields_by_name['dashboardsMetaData'].message_type = _DASHBOARDMETADATA
DESCRIPTOR.message_types_by_name['SavedSearchSPLGetRequest'] = _SAVEDSEARCHSPLGETREQUEST
DESCRIPTOR.message_types_by_name['SavedSearchSPLGetResponse'] = _SAVEDSEARCHSPLGETRESPONSE
DESCRIPTOR.message_types_by_name['SavedSearchMetaData'] = _SAVEDSEARCHMETADATA
DESCRIPTOR.message_types_by_name['SavedSearchesSyncRequest'] = _SAVEDSEARCHESSYNCREQUEST
DESCRIPTOR.message_types_by_name['SavedSearchesSyncResponse'] = _SAVEDSEARCHESSYNCRESPONSE
DESCRIPTOR.message_types_by_name['DashboardMetaData'] = _DASHBOARDMETADATA
DESCRIPTOR.message_types_by_name['DashboardsSyncRequest'] = _DASHBOARDSSYNCREQUEST
DESCRIPTOR.message_types_by_name['DashboardsSyncResponse'] = _DASHBOARDSSYNCRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SavedSearchSPLGetRequest = _reflection.GeneratedProtocolMessageType('SavedSearchSPLGetRequest', (_message.Message,), dict(
  DESCRIPTOR = _SAVEDSEARCHSPLGETREQUEST,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.SavedSearchSPLGetRequest)
  ))
_sym_db.RegisterMessage(SavedSearchSPLGetRequest)

SavedSearchSPLGetResponse = _reflection.GeneratedProtocolMessageType('SavedSearchSPLGetResponse', (_message.Message,), dict(
  DESCRIPTOR = _SAVEDSEARCHSPLGETRESPONSE,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.SavedSearchSPLGetResponse)
  ))
_sym_db.RegisterMessage(SavedSearchSPLGetResponse)

SavedSearchMetaData = _reflection.GeneratedProtocolMessageType('SavedSearchMetaData', (_message.Message,), dict(
  DESCRIPTOR = _SAVEDSEARCHMETADATA,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.SavedSearchMetaData)
  ))
_sym_db.RegisterMessage(SavedSearchMetaData)

SavedSearchesSyncRequest = _reflection.GeneratedProtocolMessageType('SavedSearchesSyncRequest', (_message.Message,), dict(
  DESCRIPTOR = _SAVEDSEARCHESSYNCREQUEST,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.SavedSearchesSyncRequest)
  ))
_sym_db.RegisterMessage(SavedSearchesSyncRequest)

SavedSearchesSyncResponse = _reflection.GeneratedProtocolMessageType('SavedSearchesSyncResponse', (_message.Message,), dict(
  DESCRIPTOR = _SAVEDSEARCHESSYNCRESPONSE,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.SavedSearchesSyncResponse)
  ))
_sym_db.RegisterMessage(SavedSearchesSyncResponse)

DashboardMetaData = _reflection.GeneratedProtocolMessageType('DashboardMetaData', (_message.Message,), dict(
  DESCRIPTOR = _DASHBOARDMETADATA,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.DashboardMetaData)
  ))
_sym_db.RegisterMessage(DashboardMetaData)

DashboardsSyncRequest = _reflection.GeneratedProtocolMessageType('DashboardsSyncRequest', (_message.Message,), dict(
  DESCRIPTOR = _DASHBOARDSSYNCREQUEST,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.DashboardsSyncRequest)
  ))
_sym_db.RegisterMessage(DashboardsSyncRequest)

DashboardsSyncResponse = _reflection.GeneratedProtocolMessageType('DashboardsSyncResponse', (_message.Message,), dict(
  DESCRIPTOR = _DASHBOARDSSYNCRESPONSE,
  __module__ = 'nlp_splapp_request_pb2'
  # @@protoc_insertion_point(class_scope:Application.DashboardsSyncResponse)
  ))
_sym_db.RegisterMessage(DashboardsSyncResponse)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)