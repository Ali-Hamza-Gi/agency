<?php

namespace App\Events;

use App\Models\User;
use Illuminate\Queue\SerializesModels;

class UserRegistered
{
    use SerializesModels;

    public $user;
    public $plainRecoveryCodes;

    public function __construct(User $user, $plainRecoveryCodes)
    {
        $this->user = $user;
        $this->plainRecoveryCodes = $plainRecoveryCodes; // So we can email them
    }
}
