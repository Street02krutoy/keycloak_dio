import 'package:dio/dio.dart';
import 'package:keycloak_dio_lib/keycloak_dio_lib.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AuthInterceptor extends Interceptor {
  final bool canRefresh;

  AuthInterceptor({this.canRefresh = false});

  @override
  void onRequest(
      RequestOptions options, RequestInterceptorHandler handler) async {
    final prefs = await SharedPreferences.getInstance();

    if (canRefresh && await KeycloakDio.shouldRefreshToken()) {
      await KeycloakDio.refresh();
    }

    options.headers.addAll({
      "Authorization": "Bearer ${prefs.getString(KeycloakDio.refreshPath)}"
    });
    return handler.next(options);
  }
}
