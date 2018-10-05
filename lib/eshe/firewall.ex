defmodule Eshe.Firewall do
  @default_firewall_record %{
    source_ip: {0, 0, 0, 0},
    source_netmask: {0, 0, 0, 0},
    dest_ip: {0, 0, 0, 0},
    dest_netmask: {0, 0, 0, 0},
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
    Module.put_attribute(module, :change_firewall_record, {:allow_record, [record]})
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
    Module.put_attribute(module, :change_firewall_record, {:deny_record, [record]})
  end

  defmacro firewall_through(identifier) do
    quote do
      :brook_pipeline.save_before_ip_filter(Eshe.Firewall, :firewall_filter)
    end
  end

  def firewall_filter(data, option) do
    filter = fetch_filter(Eshe.Supervisor.route_firewall(), :default)

    case is_allow_packet(filter, data) do
      :ok ->
        {:ok, data, option}

      error ->
        {:error, error}
    end
  end

  defp fetch_filter(route_firewall, identifier) do
    record = for %{identifier: id, record: record} <- route_firewall, identifier == id, do: record

    record
    |> List.flatten()
  end

  defp is_allow_packet([], _) do
    :ok
  end

  defp is_allow_packet([head | tail], data) do
    is_allow_packet(tail, data)
  end
end
