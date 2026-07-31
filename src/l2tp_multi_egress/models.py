from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProxyType(StrEnum):
    SHADOWSOCKS = "shadowsocks"
    SOCKS = "socks"
    HTTP = "http"


class Egress(BaseModel):
    id: str
    name: str
    type: ProxyType
    address: str
    port: Annotated[int, Field(ge=1, le=65535)]
    username: str | None = None
    password: str | None = None
    method: str | None = None

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if not NAME_RE.fullmatch(value):
            raise ValueError("ID 只能包含字母、数字、点、下划线和连字符")
        return value

    @field_validator("address")
    @classmethod
    def valid_address(cls, value: str) -> str:
        value = value.strip().strip("[]")
        if not value or any(c.isspace() for c in value):
            raise ValueError("代理地址不能为空或包含空格")
        return value

    @model_validator(mode="after")
    def protocol_fields(self) -> "Egress":
        if self.type == ProxyType.SHADOWSOCKS:
            if not self.password:
                raise ValueError("Shadowsocks 必须提供密码")
            if not self.method:
                raise ValueError("Shadowsocks 必须提供加密方式")
        return self


class Binding(BaseModel):
    id: str
    source_cidr: str
    egress_id: str
    tproxy_port: Annotated[int, Field(ge=1024, le=65535)]
    mark: Annotated[int, Field(ge=32768, le=65535)]
    enabled: bool = True
    ppp_interface: str | None = None

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if not NAME_RE.fullmatch(value):
            raise ValueError("ID 格式无效")
        return value

    @field_validator("source_cidr")
    @classmethod
    def valid_cidr(cls, value: str) -> str:
        network = ipaddress.ip_network(value, strict=True)
        if network.version != 4:
            raise ValueError("当前 TPROXY 规则仅支持 IPv4 来源网段")
        return str(network)


class AppState(BaseModel):
    revision: int = 0
    updated_at: str = Field(default_factory=utcnow)
    fake_dns: bool = False
    egresses: list[Egress] = Field(default_factory=list)
    bindings: list[Binding] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent(self) -> "AppState":
        egress_ids = [x.id for x in self.egresses]
        binding_ids = [x.id for x in self.bindings]
        if len(egress_ids) != len(set(egress_ids)):
            raise ValueError("出口 ID 重复")
        if len(binding_ids) != len(set(binding_ids)):
            raise ValueError("绑定 ID 重复")
        missing = {x.egress_id for x in self.bindings} - set(egress_ids)
        if missing:
            raise ValueError(f"绑定引用了不存在的出口: {', '.join(sorted(missing))}")
        ports = [x.tproxy_port for x in self.bindings if x.enabled]
        marks = [x.mark for x in self.bindings if x.enabled]
        if len(ports) != len(set(ports)):
            raise ValueError("启用的绑定不能共用 TPROXY 端口")
        if len(marks) != len(set(marks)):
            raise ValueError("启用的绑定不能共用 fwmark")
        networks = [(x.id, ipaddress.ip_network(x.source_cidr)) for x in self.bindings if x.enabled]
        for index, (left_id, left) in enumerate(networks):
            for right_id, right in networks[index + 1 :]:
                if left.overlaps(right):
                    raise ValueError(f"来源网段重叠: {left_id} 与 {right_id}")
        return self


class Credentials(BaseModel):
    username: str
    password: str


class Transaction(BaseModel):
    id: str
    status: Literal["pending", "confirmed", "rolled_back"] = "pending"
    deadline_epoch: float
    previous_snapshot: str
    candidate_revision: int
    created_at: str = Field(default_factory=utcnow)
