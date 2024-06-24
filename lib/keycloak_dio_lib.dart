library keycloak_dio_lib;

import 'dart:io';

import 'package:dio/dio.dart';
import 'package:jwt_decoder/jwt_decoder.dart';
import 'package:logging/logging.dart';
import 'package:openid_client/openid_client_io.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

class KeycloakDio {
  static late Dio _dio;
  static final _log = Logger('Auth');

  static late String _clientId;
  static late String _refreshPath;
  static late String _realm;
  static late String _baseUrl;

  static late String _tokenPath;

  static String get ssoUrl => "${_baseUrl}/realms/${_realm}";
  static String get refreshPath => _refreshPath;

  static Future<void> init({
    String refreshPath = "AUTH_REFRESH_TOKEN",
    required String baseUrl,
    required String realm,
    required String clientId,
    String tokenPath = "AUTH_ACCESS_TOKEN",
    bool shouldRefresh = false,
  }) async {
    if (!Platform.isAndroid) {
      throw UnsupportedError("${Platform.operatingSystem} is not supported");
    }
    _refreshPath = refreshPath;
    _clientId = clientId;
    _realm = realm;
    _baseUrl = baseUrl;
    _tokenPath = tokenPath;
    _dio = Dio(BaseOptions(baseUrl: ssoUrl));
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        final prefs = await SharedPreferences.getInstance();

        if (await shouldRefreshToken()) await refresh();

        options.headers.addAll(
            {"Authorization": "Bearer ${prefs.getString(refreshPath)}"});
        return handler.next(options);
      },
      onError: (error, handler) {
        return error.response != null
            ? handler.resolve(error.response!)
            : handler.next(error);
      },
    ));
    _log.info("Initialized authservice");
  }

  // @Deprecated("!NOT SAFE!")
  static Future<UserInfo> authorizePassword(
      {required String username, required String password}) async {
    var res = await _dio.post("/protocol/openid-connect/token",
        data: {
          "client_id": _clientId,
          "username": username,
          "password": password,
          "grant_type": "password"
        },
        options: Options(contentType: Headers.formUrlEncodedContentType));
    if (res.statusCode != 200) throw Exception(res.data);

    final prefs = await SharedPreferences.getInstance();

    prefs.setString(_tokenPath, res.data["access_token"] ?? "null");
    prefs.setString(_refreshPath, res.data["refresh_token"] ?? "null");

    return await _dio.get("/protocol/openid-connect/userinfo").then((val) {
      if (val.statusCode != 200) throw Exception(val);
      return UserInfo.fromJson(val.data);
    });
  }

  static Future<bool> refresh() async {
    final prefs = await SharedPreferences.getInstance();

    var res = await _dio.post("/protocol/openid-connect/token",
        data: {
          'client_id': _clientId,
          'refresh_token': prefs.getString(_refreshPath),
          'grant_type': 'refresh_token'
        },
        options: Options(contentType: Headers.formUrlEncodedContentType));
    if (res.statusCode == 200) {
      prefs.setString(_tokenPath, res.data["access_token"] ?? "null");
      prefs.setString(_refreshPath, res.data["refresh_token"] ?? "null");
      return true;
    }

    return false;
  }

  static Future<bool> shouldRefreshToken() async {
    final prefs = await SharedPreferences.getInstance();
    return JwtDecoder.isExpired(prefs.getString(_tokenPath) ?? "none");
  }

  static Future<UserInfo> authorizeBrowser(
      {List<String> scopes = const ['openid']}) async {
    // create the client
    var issuer = await Issuer.discover(Uri.parse(ssoUrl));
    var client = Client(issuer, _clientId);
    final prefs = await SharedPreferences.getInstance();

    urlLauncher(String uri) async {
      Uri url = Uri.parse(uri);
      if (await canLaunchUrl(url)) {
        await launchUrl(url);
      } else {
        _log.info("cannot launch $uri");
      }
    }

    // create an authenticator
    var authenticator = Authenticator(client,
        scopes: scopes, port: 4000, urlLancher: urlLauncher);

    // starts the authentication
    var c = await authenticator.authorize();

    // close the webview when finished
    closeInAppWebView();

    prefs.setString(
        _tokenPath, (await c.getTokenResponse()).accessToken ?? "null");
    prefs.setString(_refreshPath, c.refreshToken ?? "null");

    _log.info(issuer.metadata.userinfoEndpoint);
    // return the user info
    return await c.getUserInfo();
  }
}
