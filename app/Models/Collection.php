<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Collection extends Model
{
    use HasFactory;

    protected $table = 'collections';

    protected $fillable = [
        'shop_code', 
        'code', 
        'name', 
        'description', 
        'payment_used', 
        'status'
    ];

    public function billings()
    {
        return $this->hasMany(Billing::class, 'belong_to_collection', 'code');
    }

    public function shop()
    {
        return $this->belongsTo(Shop::class, 'shop_code', 'code'); // Assuming shop_code relates to code in shops table
    }
}
