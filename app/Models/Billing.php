<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Billing extends Model
{
    use HasFactory;

    // Table name (if it differs from the plural form of the model name)
    protected $table = 'billings';

    protected $fillable = [
        'code', 
        'belong_to_collection', 
        'status', 
        'amount',
        'payment_description', 
        'payment_description2', 
        'due_date',
        'payer_name', 
        'payer_email', 
        'payer_phone',
        'payment_method', // Include if this is relevant for your table structure
    ];

    // Relationship to the Collection
    public function collection()
    {
        return $this->belongsTo(Collection::class, 'belong_to_collection', 'code');
    }
}
