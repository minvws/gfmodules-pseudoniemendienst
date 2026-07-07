from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
ip_var: ContextVar[str] = ContextVar("ip", default="-")
client_trace_id_var: ContextVar[str] = ContextVar("client_trace_id", default="-")
