defmodule Eshe.Chaos do
  @default_delay_record %{
    source_ip: nil,
    source_netmask: nil,
    dest_ip: nil,
    dest_netmask: nil,
    source_port: nil,
    dest_port: nil,
    milisec: nil,
    protocol: :ip,
    rate: 100
  }

  @default_loss_record %{
    source_ip: nil,
    source_netmask: nil,
    dest_ip: nil,
    dest_netmask: nil,
    source_port: nil,
    dest_port: nil,
    protocol: :ip,
    rate: 100
  }

  defmacro chaos(identifier \\ :global, attrs \\ [], do: context) do
    do_chaos(identifier, attrs, context)
  end

  defp do_chaos(identifier, attrs, context) do
    quote do
      Module.register_attribute(__MODULE__, :change_chaos, accumulate: true)
      Module.register_attribute(__MODULE__, :change_chaos_record, accumulate: true)
      Module.register_attribute(__MODULE__, :chaos_pipeline, accumulate: true)
      identifier = unquote(identifier)
      attrs = unquote(attrs)

      Module.put_attribute(__MODULE__, :change_chaos, {:identifier, identifier})

      try do
        unquote(context)
      after
        :ok
      end

      loaded = Eshe.Chaos.__load__(__MODULE__, @change_chaos_record)
      Module.put_attribute(__MODULE__, :chaos_pipeline, loaded)

      def chaos_pipeline, do: @chaos_pipeline
    end
  end

  def __load__(module, records) do
    records = Enum.reverse(records)
    Module.put_attribute(module, :change_chaos, {:record, records})
    Map.new(Module.get_attribute(module, :change_chaos))
  end

  defmacro delay(c) do
    quote do
      c = unquote(c)
      Eshe.Chaos.__delay__(__MODULE__, Map.new(c))
    end
  end

  defmacro loss(c) do
    quote do
      c = unquote(c)
      Eshe.Chaos.__loss__(__MODULE__, Map.new(c))
    end
  end

  def __delay__(module, c) do
    record = Map.merge(@default_delay_record, c)
    Module.put_attribute(module, :change_chaos_record, {:delay, record})
  end

  def __loss__(module, c) do
    record = Map.merge(@default_loss_record, c)
    Module.put_attribute(module, :change_chaos_record, {:loss, record})
  end

  defmacro chaos_through(identifier) do
    quote do
      identifier = unquote(identifier)
      :brook_pipeline.save_before_ip_pipeline(Eshe.Chaos.chaos_pipeline(identifier))
    end
  end

  def chaos_pipeline(identifier) do
    chaos = fetch_pipeline(Eshe.Supervisor.chaos_pipeline(), identifier)

    fn data, option ->
      case chaos_pipeline(chaos, data, option) do
        {:ok, data, option} ->
          {:ok, data, option}
        err ->
          err
      end
    end
  end

  defp fetch_pipeline(route_firewall, identifier) do
    record = for %{identifier: id, record: record} <- route_firewall, identifier == id, do: record

    record
    |> List.flatten()
  end

  def chaos_pipeline([], data, option) do
    {:ok, data, option}
  end

  def chaos_pipeline([head | tail], data, option) do
    case chaos_type_pipeline(head, data, option) do
      {:ok, data, option} ->
        chaos_pipeline(tail, data, option)

      error ->
        error
    end
  end

  def chaos_type_pipeline({:delay, record}, data, option) do
    if Eshe.Firewall.match(record, data) do
      rate = record[:rate]
      ran = trunc(:rand.uniform() * 100)

      if rate >= ran do
        time = record[:milisec]
        :timer.sleep(time)
      end

      {:ok, data, option}
    else
      {:ok, data, option}
    end
  end

  def chaos_type_pipeline({:loss, record}, data, option) do
    if Eshe.Firewall.match(record, data) do
      rate = record[:rate]
      ran = trunc(:rand.uniform() * 100)
      if rate >= ran do
        {:error, {{:message, :chaos_type_loss}, {:record, record}, {:data, data}}}
      else
        {:ok, data, option}
      end
    else
      {:ok, data, option}
    end
  end

  def chaos_type_pipeline(pipe, data, option) do
    IO.inspect(pipe)
    {:ok, data, option}
  end
end
