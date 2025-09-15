
class BasePseudonym:
    def __init__(self, pseudonym: str):
        self.pseudonym = pseudonym

    def __str__(self) -> str:
        return self.pseudonym

    def __repr__(self) -> str:
        return f"BP[{self.pseudonym}]"

    def as_bytes(self) -> bytes:
        return self.pseudonym.encode()


class PDN:
    def __init__(self, pdn: str):
        self.pdn = pdn

    def __str__(self) -> str:
        return self.pdn

    def __repr__(self) -> str:
        return f"PDN[{self.pdn}]"

    def as_bytes(self) -> bytes:
        return self.pdn.encode()

class OrganizationId:
    def __init__(self, organization_id: str):
        self.organization_id = organization_id

    def __str__(self) -> str:
        return self.organization_id

    def __repr__(self) -> str:
        return f"ORGID[{self.organization_id}]"

    def as_bytes(self) -> bytes:
        return self.organization_id.encode()


class Rid:
    def __init__(self, rid: str):
        self.rid = rid

    def __str__(self) -> str:
        return self.rid

    def __repr__(self) -> str:
        return f"RID[{self.rid}]"

    def as_bytes(self) -> bytes:
        return self.rid.encode()
