defmodule Eshe.Chaos do
  @moduledoc """

  """

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

  @default_duplicate_record %{
    source_ip: nil,
    source_netmask: nil,
    dest_ip: nil,
    dest_netmask: nil,
    source_port: nil,
    dest_port: nil,
    protocol: :ip,
    rate: 100
  }

  @default_tcp_ack_record %{
    source_ip: nil,
    source_netmask: nil,
    dest_ip: nil,
    dest_netmask: nil,
    source_port: nil,
    dest_port: nil,
    protocol: :tcp,
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

  defmacro duplicate(c) do
    quote do
      c = unquote(c)
      Eshe.Chaos.__duplicate__(__MODULE__, Map.new(c))
    end
  end

  defmacro tcp_ack(c) do
    quote do
      c = unquote(c)
      Eshe.Chaos.__tcp_ack__(__MODULE__, Map.new(c))
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

  def __duplicate__(module, c) do
    record = Map.merge(@default_duplicate_record, c)
    Module.put_attribute(module, :change_chaos_record, {:duplicate, record})
  end

  def __tcp_ack__(module, c) do
    record = Map.merge(@default_tcp_ack_record, c)
    Module.put_attribute(module, :change_chaos_record, {:tcp_ack, record})
  end

  defmacro chaos_through(identifier) do
    quote do
      identifier = unquote(identifier)
      :brook_pipeline.save_before_ip_pipeline(Eshe.Chaos.chaos_pipeline(identifier))
      :brook_pipeline.save_after_send_pipeline(Eshe.Chaos, :send_after_packet)
    end
  end

  def send_after_packet(data, option) do
    dupl = Map.get(option, :duplicate, false)
    if dupl do
      <<ether :: size(112), send_data :: binary >> = data
      :brook_sender.send_packet(:ip_request, {send_data, %{option| duplicate: false}})
    end
    {:ok, data, option}
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

  def chaos_type_pipeline({:duplicate, record}, data, option) do
    if Eshe.Firewall.match(record, data) do
      rate = record[:rate]
      ran = trunc(:rand.uniform() * 100)
      if rate >= ran do
        {:ok, data, Map.merge(%{duplicate: true}, option)}
      else
        {:ok, data, option}
      end
    else
      {:ok, data, option}
    end
  end

  def chaos_type_pipeline({:tcp_ack, record}, data, option) do
    if Eshe.Firewall.match(record, data) do
      rate = record[:rate]
      ran = trunc(:rand.uniform() * 100)
      if rate >= ran and has_tcp_ack(data) == true do
        {:error, {{:message, :chaos_type_tcp_ack}, {:record, record}, {:data, data}}}
      else
        {:ok, data, option}
      end
    else
      {:ok, data, option}
    end
  end

  def chaos_type_pipeline(pipe, data, option) do
    {:ok, data, option}
  end

  def has_tcp_ack(<<_ :: size(72), 6, _ :: size(80), tcp :: size(106), _:: size(1), 1 :: size(1), _ :: binary>>) do
    false
  end
  def has_tcp_ack(_) do
    true
  end
end
