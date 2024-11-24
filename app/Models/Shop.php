<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Shop extends Model
{
    use HasFactory;

    protected $fillable = [
        'shop_code',
        'name',
        'description',
        'date_created',
        'status',
        'payment_used',
    ];

    protected $casts = [
        'payment_used' => 'array', // Cast payment_used as an array for JSON handling
    ];

    public function collections()
    {
        return $this->hasMany(Collection::class, 'shop_code');
    }
}
