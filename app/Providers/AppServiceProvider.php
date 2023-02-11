<?php

namespace App\Providers;

use Illuminate\Support\Facades\Response;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        Response::macro('apiResponse', function($e, $data = [], $message = '', $code = 500){
            $exception = $e->getMessage() . 'in' . $e->getFile() . 'as line' . $e->getLine();
            $data['data'] = $data;
            $data['status'] = false;
            $data['message'] = $message;
            $data['error'] = $message == '' ? $exception : '';
            return response()->json($data, $code);
        });
    }
}
