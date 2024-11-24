<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Shop;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class ShopController extends Controller
{
    // Fetch all shops the user has access to
    public function index(Request $request)
    {
        // Ensure the user is authenticated
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Retrieve user abilities from the token
        $userAbilities = $request->user()->currentAccessToken()->abilities;
        Log::info('User Abilities:', $userAbilities);

        $allowedShops = collect();

        // Check if the user has access to all shops
        if (in_array('*', $userAbilities)) {
            $allowedShops = Shop::all();
            Log::info('All Shops Retrieved', ['count' => $allowedShops->count()]);
            return response()->json($allowedShops);
        }

        // Filter shops based on user's specific abilities
        foreach ($userAbilities as $ability) {
            if (str_starts_with($ability, 'view-')) {
                $shopCode = str_replace('view-', '', $ability);
                Log::info('Checking Shop Code:', ['code' => $shopCode]);

                // Retrieve the shop by shop_code if it exists
                $shop = Shop::where('shop_code', $shopCode)->first();
                if ($shop) {
                    $allowedShops->push($shop);
                    Log::info('Found Shop:', ['shop' => $shop]);
                }
            }
        }

        Log::info('Allowed Shops Count:', ['count' => $allowedShops->count()]);
        return response()->json($allowedShops);
    }

    // Fetch a specific shop by ID
    public function show($id, Request $request)
    {
        // Ensure the user is authenticated
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Retrieve the shop by ID
        $shop = Shop::findOrFail($id);
        $userAbilities = $request->user()->currentAccessToken()->abilities;

        // Check if the user has the ability to view this specific shop by shop_code
        if (!in_array('view-' . $shop->shop_code, $userAbilities) && !in_array('*', $userAbilities)) {
            return response()->json(['message' => 'Unauthorized to view this shop'], 403);
        }

        return response()->json($shop);
    }
}
