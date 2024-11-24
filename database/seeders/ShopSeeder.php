<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Shop;

class ShopSeeder extends Seeder
{
    public function run()
    {
        Shop::create([
            'name' => 'Main Street Electronics',
            'description' => 'Electronics and gadgets store',
            'date_created' => now(),
            'status' => 'active',
            'payment_used' => ['OBW', 'QR']
        ]);

        Shop::create([
            'name' => 'Fashion Hub',
            'description' => 'Clothing and accessories',
            'date_created' => now(),
            'status' => 'active',
            'payment_used' => ['MPGS']
        ]);
    }
}
