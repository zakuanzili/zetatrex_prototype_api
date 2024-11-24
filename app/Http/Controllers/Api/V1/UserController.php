<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class UserController extends Controller
{
    /**
     * Save FCM Token for the authenticated user.
     */
    public function saveFCMToken(Request $request)
    {
        // Check if the user is authenticated
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Validate the FCM token
        $request->validate([
            'fcm_token' => 'required|string',
        ]);

        // Get the authenticated user
        $user = $request->user();

        if ($user) {
            // If the user already has an FCM token, remove it
            if ($user->fcm_token) {
                $user->fcm_token = null;
            }

            // Update the FCM token with the new one
            $user->fcm_token = $request->fcm_token;
            $user->save();

            Log::info('FCM Token saved for user:', ['user_id' => $user->id]);

            return response()->json(['message' => 'FCM Token saved successfully'], 200);
        }

        return response()->json(['message' => 'User not found'], 404);
    }
}
