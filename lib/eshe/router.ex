defmodule Eshe.Router do
  defmacro static(identifier \\ "global", attrs \\ [], do: context) do
    IO.inspect identifier
    do_static(identifier, attrs, context)
    # interface_ip:
    # dest_ip:
    # dest_prefix:
    # interface:
  end

  def record!(module, identifier, attrs, context) do
  end

  defp do_static(identifier, attrs, block) do
    IO.inspect "do static"
    record!(__MODULE__, identifier, attrs, block)
  end

  # route(add, static, #{dest_route := {D1, D2, D3, D4}, subnetmask := {S1, S2, S3, S4},
  # nexthop := Nexthop, out_interface := OutInterface}) ->
  defmacro add(c) when is_list(c) do
    IO.inspect "add is list"
    IO.inspect c
  end

  defmacro add(c) when is_map(c) do
    IO.inspect "add is map"
    IO.inspect c
  end
end

