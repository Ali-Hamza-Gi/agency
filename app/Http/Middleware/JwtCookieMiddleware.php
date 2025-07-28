<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use App\Helpers\ApiResponse;

class JwtCookieMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->cookie(config('jwt.cookie', 'token'));

        if (!$token) {
            return ApiResponse::error('No active session found. Please log in to continue.', 401);
        }

        try {
            JWTAuth::setToken($token)->authenticate();
        } catch (TokenExpiredException $e) {
            return ApiResponse::error('Your session has expired. Please log in again.', 401);
        } catch (TokenInvalidException $e) {
            return ApiResponse::error('Invalid authentication token. Please log in again.', 401);
        } catch (JWTException $e) {
            return ApiResponse::error('Authentication failed. Please log in again.', 401);
        }

        return $next($request);
    }
}
