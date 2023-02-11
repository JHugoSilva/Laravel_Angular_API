<?php

namespace App\Exceptions;

use ErrorException;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Throwable;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array<int, class-string<Throwable>>
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     *
     * @return void
     */
    public function register()
    {
        $this->reportable(function (Throwable $e) {

        });
    }

    public function render($request, Throwable $e) {
        if (Str::contains($request->url(), '/api')) {
            if ($e instanceof ErrorException) return response()->apiResponse($e);

            elseif($e instanceof NotFoundHttpException) return response()->apiResponse($e, [], 'Not Found', 404);

            elseif($e instanceof ThrottleRequestsException) return response()->apiResponse($e, [], 'Not Found', 404);
        }
        return parent::render($request, $e);
    }
}
