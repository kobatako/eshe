defmodule Eshe.Firewall do
  @moduledoc """

  firewall :default do
    allow(
      source_ip: {192, 168, 0, 0},
      source_netmask: {255, 255, 255, 0}
    )
    deny(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0}
    )
    deny()
  end

  """

  use Bitwise

  @default_firewall_record %{
    source_ip: nil,
    source_netmask: nil,
    dest_ip: nil,
    dest_netmask: nil,
    source_port: nil,
    dest_port: nil,
    protocol: nil
  }

  defmacro firewall(identifier, attrs \\ [], do: context) do
    do_firewall(identifier, attrs, context)
  end

  defp do_firewall(identifier, attrs, context) when is_atom(identifier) do
    quote do
      Module.register_attribute(__MODULE__, :change_firewall, accumulate: true)
      Module.register_attribute(__MODULE__, :change_firewall_record, accumulate: true)
      Module.register_attribute(__MODULE__, :route_firewall, accumulate: true)

      identifier = unquote(identifier)
      attrs = unquote(attrs)

      Module.put_attribute(__MODULE__, :change_firewall, {:identifier, identifier})

      try do
        unquote(context)
      after
        :ok
      end

      loaded = Eshe.Firewall.__load__(__MODULE__, @change_firewall_record)
      Module.put_attribute(__MODULE__, :route_firewall, loaded)

      def route_firewall, do: @route_firewall
    end
  end

  def __load__(module, records) do
    records = Enum.reverse(records)
    Module.put_attribute(module, :change_firewall, {:record, records})
    Map.new(Module.get_attribute(module, :change_firewall))
  end

  defmacro allow(c) do
    quote do
      Eshe.Firewall.__allow__(__MODULE__, Map.new(unquote(c)))
    end
  end

  def __allow__(module, c) do
    record = Map.merge(@default_firewall_record, c)
    Module.put_attribute(module, :change_firewall_record, {:allow_record, record})
  end

  defmacro deny() do
    quote do
      Eshe.Firewall.__deny__(__MODULE__, %{})
    end
  end

  defmacro deny(c) do
    quote do
      Eshe.Firewall.__deny__(__MODULE__, Map.new(unquote(c)))
    end
  end

  def __deny__(module, c) do
    record = Map.merge(@default_firewall_record, c)
    Module.put_attribute(module, :change_firewall_record, {:deny_record, record})
  end

  defmacro firewall_through(identifier) do
    quote do
      identifier = unquote(identifier)
      :brook_pipeline.save_after_ip_filter(Eshe.Firewall.firewall_filter(identifier))
    end
  end

  def firewall_filter(identifier) do
    filter = fetch_filter(Eshe.Supervisor.route_firewall(), identifier)

    fn(data, option) ->
      case is_allow_filter(filter, data) do
        :ok ->
          {:ok, data, option}

        error ->
          {:error, error}
      end
    end
  end

  defp fetch_filter(route_firewall, identifier) do
    record = for %{identifier: id, record: record} <- route_firewall, identifier == id, do: record

    record
    |> List.flatten()
  end

  defp is_allow_filter([], _) do
    :ok
  end

  defp is_allow_filter([head | tail], data) do
    case record_filter(head, data) do
      :ok ->
        :ok
      :error ->
        {:error, :bad_match}
      :next ->
        is_allow_filter(tail, data)
    end
  end

  defp record_filter({:deny_record, record}, data) do
    if !match(record, data) do
      :next
    else
      :error
    end
  end

  defp record_filter({:allow_record, record}, data) do
    if match(record, data) do
      :ok
    else
      :next
    end
  end


  @doc """

    is match packet filter record

    # Exsample

    destanation ip and source ip is nil
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: nil,
    ...>      dest_netmask: nil,
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: nil,
    ...>      source_netmask: nil,
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    false

    match to destanation ip and source ip is nil
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: {192, 168, 10, 0},
    ...>      dest_netmask: {255, 255, 255, 0},
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: nil,
    ...>      source_netmask: nil,
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    true

    not match destanation ip and source ip is nil
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: {192, 168, 0, 0},
    ...>      dest_netmask: {255, 255, 255, 0},
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: nil,
    ...>      source_netmask: nil,
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    false

    destanation ip is nil and match to source ip
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: nil,
    ...>      dest_netmask: nil,
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: {192, 168, 20, 0},
    ...>      source_netmask: {255, 255, 255, 0},
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    true

    destanation ip is nil and not match source ip
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: nil,
    ...>      dest_netmask: nil,
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: {192, 168, 0, 0},
    ...>      source_netmask: {255, 255, 255, 0},
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    false

    match to destanation ip and match to source ip
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: {192, 168, 10, 0},
    ...>      dest_netmask: {255, 255, 255, 0},
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: {192, 168, 20, 0},
    ...>      source_netmask: {255, 255, 255, 0},
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    true

    match to destanation ip and not match source ip
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: {192, 168, 10, 0},
    ...>      dest_netmask: {255, 255, 255, 0},
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: {192, 168, 0, 0},
    ...>      source_netmask: {255, 255, 255, 0},
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    false

    not match destanation ip and match to source ip
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: {192, 168, 0, 0},
    ...>      dest_netmask: {255, 255, 255, 0},
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: {192, 168, 10, 0},
    ...>      source_netmask: {255, 255, 255, 0},
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    false

    not match destanation ip and not match source ip
    iex> Eshe.Firewall.match(%{
    ...>      dest_ip: {192, 168, 0, 0},
    ...>      dest_netmask: {255, 255, 255, 0},
    ...>      dest_port: nil,
    ...>      protocol: nil,
    ...>      source_ip: {192, 168, 0, 0},
    ...>      source_netmask: {255, 255, 255, 0},
    ...>      source_port: nil
    ...>  }, <<0 :: size(96), 192, 168, 20, 10, 192, 168, 10, 10>>)
    false

  """
  def match(record, <<_head :: size(96), source_ip :: size(32), dest_ip :: size(32), other :: binary>>) do
    with res <- match_ip([], record[:dest_ip], record[:dest_netmask], dest_ip),
     res <- match_ip(res, record[:source_ip], record[:source_netmask], source_ip),
     res <- Enum.filter(res, &(&1 != nil)),
    {:ok, _value} <- Enum.fetch(res, 0)
    do
      Enum.all?(res, fn r -> r == true end)
    else
      _ ->
        false
    end
  end

  @doc """

    # Exsample

    iex> Eshe.Firewall.match_ip([], {192, 168, 10, 0}, {255, 255, 255, 0},
    ...> Eshe.Firewall.trace_to_integer_ip_addr({192, 168, 10, 10}))
    [true]

    iex> Eshe.Firewall.match_ip([], nil, {255, 255, 255, 0},
    ...> Eshe.Firewall.trace_to_integer_ip_addr({192, 168, 10, 10}))
    [nil]

    iex> Eshe.Firewall.match_ip([], {192, 168, 0, 0}, {255, 255, 255, 0},
    ...> Eshe.Firewall.trace_to_integer_ip_addr({192, 168, 10, 10}))
    [false]

    iex> Eshe.Firewall.match_ip([], {192, 168, 10, 0}, {255, 255, 0, 0},
    ...> Eshe.Firewall.trace_to_integer_ip_addr({192, 168, 10, 10}))
    [false]

  """
  def match_ip(res, record_ip, record_netmask, ip) do
    if nil == record_ip do
      [nil| res]
    else
      if band(trace_to_integer_ip_addr(record_netmask), ip)
      == trace_to_integer_ip_addr(record_ip)  do
        [true| res]
      else
        [false| res]
      end
    end
  end

  def trace_to_tuple_ip_addr(ip) when is_integer(ip) do
    <<i1, i2, i3, i4>> = <<ip :: size(32)>>
    {i1, i2, i3, i4}
  end

  def trace_to_integer_ip_addr({i1, i2, i3, i4}) do
    <<ip :: size(32)>> = <<i1, i2, i3, i4>>
    ip
  end

  def trace_to_integer_ip_addr(ip) do
    ip
  end
end
