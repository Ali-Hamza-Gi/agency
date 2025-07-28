<?php

namespace App\Listeners;

use App\Events\UserRegistered;
use Log;

class GenerateRecoveryCodes
{
    public function handle(UserRegistered $event)
    {
        $codes = \App\Models\User::generateRecoveryCodes();
        $event->user->two_factor_recovery_codes = json_encode(array_map(fn($c) => ['hashed' => $c['hashed']], $codes));
        $event->user->save();
        Log::info($event->plainRecoveryCodes);
        // You can email the plain codes to the user
        // Mail::to($event->user->email)->send(new SendRecoveryCodes($event->plainRecoveryCodes));
    }
}
