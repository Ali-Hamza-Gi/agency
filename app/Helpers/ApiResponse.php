<?php

namespace App\Helpers;

use Illuminate\Support\MessageBag;

/**
 * Class ApiResponse
 *
 * A helper class to standardize API responses for success, errors, and validation failures.
 */
class ApiResponse
{
    /**
     * Success Response
     *
     * @param array $data       Data to be returned with the response
     * @param string $message   Success message
     * @param int $statusCode   HTTP status code (default 200)
     * @return \Illuminate\Http\JsonResponse
     */
    public static function success($data = [], $message = 'Success', $statusCode = 200)
    {
        return response()->json([
            'status' => true,       // Indicates success
            'message' => $message,  // Response message
            'data' => $data,        // Actual data to return
        ], $statusCode);
    }

    /**
     * Error Response
     *
     * @param string $message    Error message
     * @param int $statusCode    HTTP status code (default 400)
     * @param array $errors      Additional error details (optional)
     * @return \Illuminate\Http\JsonResponse
     */
    public static function error($message = 'An error occurred', $statusCode = 400, $errors = [])
    {
        return response()->json([
            'status' => false,      // Indicates failure
            'message' => $message,  // Error message
            'errors' => $errors,    // Additional error details (optional)
        ], $statusCode);
    }

    /**
     * Validation Error Response
     *
     * Handles Laravel validation errors (MessageBag) and converts them
     * into a simple array with only the first error for each field.
     *
     * @param \Illuminate\Support\MessageBag|array $errors   Validation errors
     * @param string $message                              Error message
     * @param int $statusCode                              HTTP status code (default 422)
     * @return \Illuminate\Http\JsonResponse
     */
    public static function validationError($errors, $message = 'Validation errors', $statusCode = 422)
    {
        // Convert MessageBag instance to array if needed
        if ($errors instanceof MessageBag) {
            $errors = $errors->toArray();
        }

        // Extract only the first error message for each field
        $errors = array_map(fn($message) => is_array($message) ? $message[0] : $message, $errors);

        return response()->json([
            'status' => false,      // Indicates failure
            'message' => $message,  // Validation error message
            'errors' => $errors,    // Field-wise errors (only first message)
        ], $statusCode);
    }
}
