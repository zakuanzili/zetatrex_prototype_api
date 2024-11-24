<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Transaction extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'code', // Allow mass assignment for 'code'
        'status',
        'amount',
        'payment_description',
        'payment_description2', // Include the new column if applicable
        'due_date',
        'payer_name',
        'payer_email',
        'payer_phone',
    ];
}
