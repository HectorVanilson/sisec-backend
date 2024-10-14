<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UsersController;
use App\Http\Controllers\TasksController;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/




Route::prefix('v1')->group(function () {
    Route::post('/register',  [UsersController::class, 'store']);
    Route::post('/loginuser',  [UsersController::class, 'login']);
});

Route::middleware('auth:api')->prefix('v1')->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
    Route::post('/logout',  [UsersController::class, 'logout']);

    Route::apiResource('/tasks', TasksController::class);
    Route::get('/tasks/status/{status}', [TasksController::class, 'filterByStatus']);
});
// Rotas de autenticação e recuperação de senha
Route::post('/login', [AuthController::class, 'login']);
Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
Route::post('/reset-password', [AuthController::class, 'resetPassword']);
