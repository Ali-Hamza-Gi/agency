<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    |
    | Controls how your API responds to cross-origin requests. You may adjust
    | the settings below as needed for your frontend apps and environments.
    |
    */

    'paths' => ['api/*', 'sanctum/csrf-cookie', 'login', 'logout'], // Add extra paths if needed

    'allowed_methods' => ['*'], // Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)

    'allowed_origins' => ['*'], // ⚠️ Development only. Replace with exact domains in production.

    'allowed_origins_patterns' => [],

    'allowed_headers' => ['*'], // Allow all headers (or restrict if needed)

    'exposed_headers' => [],

    'max_age' => 0,

    'supports_credentials' => true, // Important for HttpOnly cookies & sessions

];
