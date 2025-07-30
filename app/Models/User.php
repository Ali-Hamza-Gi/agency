<?php

namespace App\Models;

use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\SoftDeletes;
use App\Notifications\TwoFactorCodeNotification;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable, SoftDeletes;

    protected $fillable = [
        'agency_id',
        'name',
        'email',
        'password',
        'profile_image',
        'role',
        'status',
        'email_verified_at',
        'last_login_at',
        'last_login_ip',
        'failed_login_attempts',
        'locked_until',
        'two_factor_enabled',
        'is_two_factor_verified',
        'two_factor_secret',
        'two_factor_code',
        'two_factor_expires_at',
        'two_factor_recovery_codes',
        'timezone',
        'language',
        'created_by',
        'updated_by',
        'deleted_by',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_code',
        'two_factor_recovery_codes',
    ];

    protected $casts = [
        'email_verified_at'        => 'datetime',
        'last_login_at'            => 'datetime',
        'locked_until'             => 'datetime',
        'two_factor_expires_at'    => 'datetime',
        'two_factor_enabled'       => 'boolean',
        'is_two_factor_verified'   => 'boolean',
        'failed_login_attempts'    => 'integer',
        'password'                 => 'hashed',
    ];

    /**
     * Generate & hash recovery codes.
     */
    public static function generateRecoveryCodes($count = 8)
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $plain = strtoupper(Str::random(10));
            $codes[] = [
                'plain' => $plain,
                'hashed' => Hash::make($plain),
            ];
        }
        return $codes;
    }

    /**
     * Verify a recovery code.
     */
    public function verifyRecoveryCode($code): bool
    {
        $codes = json_decode($this->two_factor_recovery_codes, true) ?? [];
        foreach ($codes as $index => $stored) {
            if (Hash::check($code, $stored['hashed'])) {
                // Remove the used code (one-time use)
                unset($codes[$index]);
                $this->two_factor_recovery_codes = json_encode(array_values($codes));
                $this->save();
                return true;
            }
        }
        return false;
    }


    /**
     * Generate a temporary 2FA code (for email).
     */
    public function generateTwoFactorCode()
    {
        $plainCode = rand(100000, 999999);

        $this->two_factor_code = Hash::make($plainCode); // store hashed
        $this->two_factor_expires_at = now()->addMinutes(10);
        $this->save();

        // Send the *plain* code to the user
        $this->notify(new TwoFactorCodeNotification($plainCode));
    }

    /**
     * Reset 2FA code after verification.
     */
    public function resetTwoFactorCode()
    {
        $this->two_factor_code = null;
        $this->two_factor_expires_at = null;
        $this->is_two_factor_verified = true;
        $this->save();
    }

    /**
     * Check if 2FA code is valid.
     */
    public function verifyTwoFactorCode($code): bool
    {
        return $this->two_factor_code && $this->two_factor_expires_at && now()->lessThanOrEqualTo($this->two_factor_expires_at) && Hash::check($code, $this->two_factor_code);
    }

    /**
     * Increment Token Version
     */
    public function incrementTokenVersion(): void
    {
        $this->token_version++;
        $this->save();
    }



    /**
     * Relationships.
     */
    public function agency()
    {
        return $this->belongsTo(User::class, 'agency_id');
    }

    public function createdBy()
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function updatedBy()
    {
        return $this->belongsTo(User::class, 'updated_by');
    }

    public function deletedBy()
    {
        return $this->belongsTo(User::class, 'deleted_by');
    }

    /**
     * Accessor for full profile image URL.
     */
    public function getProfileImageUrlAttribute(): ?string
    {
        return $this->profile_image ? asset("storage/{$this->profile_image}") : null;
    }

    /**
     * Helper: Check if account is locked.
     */
    public function isLocked(): bool
    {
        return $this->locked_until && now()->lessThan($this->locked_until);
    }

    /**
     * JWT Methods.
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims(): array
    {
        return [
            'token_version' => $this->token_version
        ];
    }
}
