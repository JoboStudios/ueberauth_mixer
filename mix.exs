defmodule UeberauthMixer.MixProject do
  use Mix.Project

  @version "0.0.1"

  def project do
    [
      app: :ueberauth_mixer,
      version: @version,
      name: "Ueberauth Mixer",
      package: package(),
      elixir: "~> 1.3",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ueberauth, :oauth2]
    ]
  end

  defp deps do
    [
      {:oauth2, "~> 1.0"},
      {:ueberauth, "~> 0.6.0"},

      # dev/test only dependencies
      {:credo, "~> 0.8", only: [:dev, :test]},

      # docs dependencies
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp docs do
    [extras: ["README.md"]]
  end

  defp description do
    "An Ueberauth strategy for using Mixer to authenticate your users."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Jimmy Bosse"],
      licenses: ["DWYW"]
    ]
  end
end
