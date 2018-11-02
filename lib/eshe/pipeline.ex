defmodule Eshe.Pipeline do
  @moduledoc """

  pipe :def do
    line(
      filter: :after_ip,
      module: Eshe.Pipeline,
      func: :test_after_ip
    )

    line(
      filter: :before_ip,
      module: Eshe.Pipeline,
      func: :test_before_ip
    )

  end

  def init() do
    pipeline_through(:def)
  end

  """

  @undefined :__undefind__

  def undefined do
    @undefined
  end

  defmacro pipe(identifier, attrs \\ [], do: context) do
    do_pipe(identifier, attrs, context)
  end

  defp do_pipe(identifier, attrs, context) do
    quote do
      Module.register_attribute(__MODULE__, :change_pipeline, accumulate: true)
      Module.register_attribute(__MODULE__, :change_pipeline_record, accumulate: true)
      Module.register_attribute(__MODULE__, :route_pipeline, accumulate: true)

      identifier = unquote(identifier)
      attrs = unquote(attrs)

      Module.put_attribute(__MODULE__, :change_pipeline, {:identifier, identifier})

      try do
        unquote(context)
      after
        :ok
      end

      loaded = Eshe.Pipeline.__load__(__MODULE__, @change_pipeline_record, attrs)
      Module.put_attribute(__MODULE__, :route_pipeline, loaded)

      def route_pipeline, do: @route_pipeline
    end
  end

  def __load__(_module, nil) do
    %{}
  end

  def __load__(module, records, attrs) do
    records = for rec <- Enum.reverse(records), do: merge_attribute(rec, attrs)
    Module.put_attribute(module, :change_pipeline, {:record, records})
    Map.new(Module.get_attribute(module, :change_pipeline))
  end

  defp merge_attribute(record, attrs) do
    filter = Keyword.get(attrs, :filter, nil)
    record = Keyword.merge([flter: filter], record)
    record
  end

  defmacro line(c) do
    quote do
      c = unquote(c)
      Eshe.Pipeline.__line__(__MODULE__, Map.new(c))
    end
  end

  def __line__(module, %{filter: _filter, func: _func, module: _module} = record) do
    Module.put_attribute(module, :change_pipeline_record, record)
  end

  def __line__(module, %{filter: _filter, func: _func} = record) do
    Module.put_attribute(module, :change_pipeline_record, Map.merge(%{module: __MODULE__}, record))
  end

  defmacro pipeline_through(identifier) do
    quote do
      pipeline = Eshe.Pipeline.fetch_filter(__MODULE__.route_pipeline(), unquote(identifier))
      before_ip_filter =  for  %{filter: :before_ip, module: module, func: func} <- pipeline, do: %{module: module, func: func}
      after_ip_filter =  for  %{filter: :after_ip, module: module, func: func} <- pipeline, do: %{module: module, func: func}
      after_send_filter =  for  %{filter: :after_send, module: module, func: func} <- pipeline, do: %{module: module, func: func}

      before_ip_pipeline_filter(before_ip_filter)
      after_ip_pipeline_filter(after_ip_filter)
      after_send_pipeline_filter(after_send_filter)
    end
  end

  def before_ip_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_before_ip_filter(module, func)
  end

  def after_ip_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_after_ip_filter(module, func)
  end

  def after_send_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_after_send_filter(module, func)
  end

  def before_tcp_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_before_tcp_filter(module, func)
  end

  def after_tcp_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_after_tcp_filter(module, func)
  end


  def before_udp_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_before_udp_filter(module, func)
  end

  def after_udp_pipeline(filter) do
    for %{module: module, func: func} <- filter, do: :brook_pipeline.save_after_udp_filter(module, func)
  end

  def fetch_filter(route_pipeline, identifier) do
    record = for %{identifier: id, record: record} <- route_pipeline, identifier == id, do: record
    record
    |> List.flatten()
  end
end

