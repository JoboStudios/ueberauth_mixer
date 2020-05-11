defmodule Ueberauth.Strategy.Mixer do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with Mixer.

  ### Setup

  Create an application in Mixer for you to use.

  Register a new application at: [your mixer developer page](https://mixer.com/settings/developers) and get the `client_id` and `client_secret`.

  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          mixer: { Ueberauth.Strategy.Mixer, [] }
        ]

  Then include the configuration for mixer.

      config :ueberauth, Ueberauth.Strategy.Mixer.OAuth,
        client_id: System.get_env("GITHUB_CLIENT_ID"),
        client_secret: System.get_env("GITHUB_CLIENT_SECRET")

  If you haven't already, create a pipeline and setup routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider/callback", AuthController, :callback
      end


  Create an endpoint for the callback where you will handle the `Ueberauth.Auth` struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback_phase(%{ assigns: %{ ueberauth_failure: fails } } = conn, _params) do
          # do things with the failure
        end

        def callback_phase(%{ assigns: %{ ueberauth_auth: auth } } = conn, params) do
          # do things with the auth
        end
      end

  You can edit the behaviour of the Strategy by including some options when you register your provider.

  To set the `uid_field`

      config :ueberauth, Ueberauth,
        providers: [
          mixer: { Ueberauth.Strategy.Mixer, [uid_field: :email] }
        ]

  Default is `:id`

  To set the default 'scopes' (permissions):

      config :ueberauth, Ueberauth,
        providers: [
          mixer: { Ueberauth.Strategy.Mixer, [default_scope: "user,public_repo"] }
        ]

  Default is empty ("") which "Grants read-only access to public information (includes public user profile info, public repository info, and gists)"
  """
  use Ueberauth.Strategy,
    uid_field: :id,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.Mixer.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the mixer authentication page.

  To customize the scope (permissions) that are requested by mixer include them as part of your url:

      "/auth/mixer?scope=user,public_repo,gist"

  You can also include a `state` param that mixer will return to you.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn), scope: scopes]
      else
        [scope: scopes]
      end

    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from Mixer. When there is a failure from Mixer the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from Mixer is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn)]
      else
        []
      end

    token = apply(module, :get_token!, [[code: code], opts])

    if token.access_token == nil do
      set_errors!(conn, [
        error(token.other_params["error"], token.other_params["error_description"])
      ])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Mixer response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:mixer_user, nil)
    |> put_private(:mixer_token, nil)
  end

  @doc """
  Fetches the uid field from the Mixer response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    conn.private.mixer_user["id"]
  end

  @doc """
  Includes the credentials from the Mixer response.
  """
  def credentials(conn) do
    token = conn.private.mixer_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.mixer_user

    %Info{
      name: user["username"],
      nickname: user["username"],
      urls: %{
        avatar_url: user["avatarUrl"]
      }
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Mixer callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.mixer_token,
        user: conn.private.mixer_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :mixer_token, token)

    with {:ok, %OAuth2.Response{status_code: status_code, body: user}} <-
           Ueberauth.Strategy.Mixer.OAuth.get(token, "/users/current") do
      put_private(conn, :mixer_user, user)
    else
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      error ->
        set_errors!(conn, [error("token", "unknown error")])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
