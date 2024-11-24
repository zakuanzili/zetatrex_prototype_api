<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Collection;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log; // Logging added

class CollectionController extends Controller
{
    // Fetch all collections the user has access to
    public function index(Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $userAbilities = $request->user()->currentAccessToken()->abilities;
        Log::info('User Abilities:', $userAbilities);

        $allowedCollections = collect();

        if (in_array('*', $userAbilities)) {
            $allowedCollections = Collection::with('billings')->get();
            Log::info('All Collections Retrieved:', ['count' => $allowedCollections->count()]);
            return response()->json($allowedCollections);
        }

        foreach ($userAbilities as $ability) {
            if (str_starts_with($ability, 'view-')) {
                $shopCode = str_replace('view-', '', $ability);
                Log::info('Checking Shop Code:', ['shop_code' => $shopCode]);

                $collection = Collection::with('billings')->where('shop_code', $shopCode)->first();
                if ($collection) {
                    $allowedCollections->push($collection);
                    Log::info('Found Collection with Shop Code:', ['collection' => $collection]);
                }
            }
        }

        Log::info('Allowed Collections Count:', ['count' => $allowedCollections->count()]);
        return response()->json($allowedCollections);
    }

    public function listCollections(Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $userAbilities = $request->user()->currentAccessToken()->abilities;
        Log::info('User Abilities:', $userAbilities);

        $allowedCollections = collect();

        if (in_array('*', $userAbilities)) {
            $allowedCollections = Collection::all();
            Log::info('All Collections Retrieved:', ['count' => $allowedCollections->count()]);
            return response()->json($allowedCollections);
        }

        foreach ($userAbilities as $ability) {
            if (str_starts_with($ability, 'view-')) {
                $shopCode = str_replace('view-', '', $ability);
                Log::info('Checking Shop Code:', ['shop_code' => $shopCode]);

                $collection = Collection::where('shop_code', $shopCode)->first();
                if ($collection) {
                    $allowedCollections->push($collection);
                    Log::info('Found Collection:', ['collection' => $collection]);
                }
            }
        }

        Log::info('Allowed Collections Count:', ['count' => $allowedCollections->count()]);
        return response()->json($allowedCollections);
    }

    public function getCollectionsByShopCode($shopCode, Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        Log::info('User Abilities:', $request->user()->currentAccessToken()->abilities);
        Log::info('Requested Shop Code:', ['shop_code' => $shopCode]);

        // Check user permissions
        if (!in_array('*', $request->user()->currentAccessToken()->abilities) &&
            !in_array('view-' . $shopCode, $request->user()->currentAccessToken()->abilities)) {
            return response()->json(['message' => 'Unauthorized to view collections for this shop code'], 403);
        }

        // Fetch collections based on shop_code
        $collections = Collection::where('shop_code', $shopCode)->get();

        if ($collections->isEmpty()) {
            return response()->json(['message' => 'No collections found for this shop code'], 404);
        }

        Log::info('Found Collections:', ['collections_count' => $collections->count()]);
        return response()->json($collections);
    }

    public function getCollectionsByShopCodeWithBillings($shopCode, Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        Log::info('User Abilities:', $request->user()->currentAccessToken()->abilities);
        Log::info('Requested Shop Code:', ['shop_code' => $shopCode]);

        // Check user permissions
        if (!in_array('*', $request->user()->currentAccessToken()->abilities) &&
            !in_array('view-' . $shopCode, $request->user()->currentAccessToken()->abilities)) {
            return response()->json(['message' => 'Unauthorized to view collections for this shop code'], 403);
        }

        // Fetch collections based on shop_code
        $collections = Collection::where('shop_code', $shopCode)->with('billings')->get();

        if ($collections->isEmpty()) {
            return response()->json(['message' => 'No collections found for this shop code'], 404);
        }

        Log::info('Found Collections:', ['collections_count' => $collections->count()]);
        return response()->json($collections);
    }

    // Fetch all collections with their associated billings based on user abilities
    public function listCollectionsWithBillings(Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $userAbilities = $request->user()->currentAccessToken()->abilities;
        Log::info('User Abilities:', $userAbilities);

        $allowedCollections = collect();

        // If user has a wildcard '*' ability, fetch all collections with their billings
        if (in_array('*', $userAbilities)) {
            $allowedCollections = Collection::with('billings')->get();
            Log::info('All Collections with Billings Retrieved:', ['count' => $allowedCollections->count()]);
            return response()->json($allowedCollections);
        }

        // Filter collections based on shop_code abilities and include their billings
        foreach ($userAbilities as $ability) {
            if (str_starts_with($ability, 'view-')) {
                $shopCode = str_replace('view-', '', $ability);
                Log::info('Checking Shop Code:', ['shop_code' => $shopCode]);

                // Retrieve collection by shop_code and eager load billings
                $collection = Collection::with('billings')
                    ->where('shop_code', $shopCode)
                    ->first();

                if ($collection) {
                    $allowedCollections->push($collection);
                    Log::info('Found Collection with Billings:', ['collection' => $collection]);
                }
            }
        }

        Log::info('Allowed Collections with Billings Count:', ['count' => $allowedCollections->count()]);
        return response()->json($allowedCollections);
    }

    public function listBillingsByCollectionCode($collectionCode, Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        Log::info('User Abilities:', $request->user()->currentAccessToken()->abilities);
        Log::info('Requested Collection Code:', ['collectionCode' => $collectionCode]);

        $collection = Collection::where('code', $collectionCode)->first();

        if (!$collection) {
            return response()->json(['message' => 'Collection not found'], Response::HTTP_NOT_FOUND);
        }

        if (in_array('*', $request->user()->currentAccessToken()->abilities) ||
            in_array('view-' . $collection->shop_code, $request->user()->currentAccessToken()->abilities)) {
            $billings = $collection->billings;
            return response()->json($billings);
        }

        Log::info('Unauthorized to view collection billing', ['collectionCode' => $collectionCode]);
        return response()->json(['message' => 'Unauthorized to view this collection billing'], 403);
    }

    // Fetch a specific collection by ID
    public function show($id, Request $request)
    {
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $collection = Collection::with('billings')->findOrFail($id);

        $userAbilities = $request->user()->currentAccessToken()->abilities;

        if (!in_array('view-' . $collection->code, $userAbilities)) {
            return response()->json(['message' => 'Unauthorized to view this collection'], 403);
        }

        return response()->json($collection);
    }

    // Create a new collection (POST)
    public function store(Request $request)
    {
        $request->validate([
            'code' => 'required|string|size:12|unique:collections,code',
            'name' => 'required|string',
            'description' => 'nullable|string',
            'status' => 'required|in:active,inactive',
        ]);

        $collection = Collection::create([
            'code' => $request->input('code'),
            'name' => $request->input('name'),
            'description' => $request->input('description'),
            'status' => $request->input('status'),
        ]);

        return response()->json($collection, Response::HTTP_CREATED);
    }

    // Update an existing collection (PUT/PATCH)
    public function update(Request $request, $id)
    {
        $collection = Collection::find($id);

        if (!$collection) {
            return response()->json(['message' => 'Collection not found'], Response::HTTP_NOT_FOUND);
        }

        $request->validate([
            'code' => 'required|string|size:12|unique:collections,code,' . $collection->id,
            'name' => 'required|string',
            'description' => 'nullable|string',
            'status' => 'required|in:active,inactive',
        ]);

        $collection->update([
            'code' => $request->input('code'),
            'name' => $request->input('name'),
            'description' => $request->input('description'),
            'status' => $request->input('status'),
        ]);

        return response()->json($collection, Response::HTTP_OK);
    }

    // Delete a collection (DELETE)
    public function destroy($id)
    {
        $collection = Collection::find($id);

        if (!$collection) {
            return response()->json(['message' => 'Collection not found'], Response::HTTP_NOT_FOUND);
        }

        $collection->delete();

        return response()->json(['message' => 'Collection deleted successfully'], Response::HTTP_OK);
    }
}
