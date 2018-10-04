defmodule Eshe.MixProject do
  use Mix.Project

  def project do
    [
      app: :eshe,
      version: "0.1.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {Eshe, []},
      extra_applications: [:logger, :brook]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      {:brook, git: "https://github.com/kobatako/brook.git", branch: "master"},
    ]
  end
end
