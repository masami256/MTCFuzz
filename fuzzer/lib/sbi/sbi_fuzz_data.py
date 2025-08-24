class SBIFuzzData:
    def __init__(self, *, eid: int = 0x0, fid: int = 0x0, a0: int = 0x0,
                  a1: int = 0x0, a2: int = 0x0, a3: int = 0x0, a4: int = 0x0, a5: int = 0x0) -> None:
        self.eid = eid
        self.fid = fid
        self.a0 = a0
        self.a1 = a1
        self.a2 = a2
        self.a3 = a3
        self.a4 = a4
        self.a5 = a5
        self.error = 0x0
        self.value = 0x0
    
    @staticmethod
    def to_json(obj: "SBIFuzzData") -> dict:
        return {
            "eid": str(hex(obj.eid)),
            "fid": str(hex(obj.fid)),
            "a0": str(hex(obj.a0)),
            "a1": str(hex(obj.a1)),
            "a2": str(hex(obj.a2)),
            "a3": str(hex(obj.a3)),
            "a4": str(hex(obj.a4)),
            "a5": str(hex(obj.a5)),
        }