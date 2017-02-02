<?php

namespace ApiBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use FOS\RestBundle\Util\ExceptionValueMap;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Log\DebugLoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;


/**
 * Custom ExceptionController that supports HTTP response status code mapping.
 */
class ApiExceptionController extends Controller
{
    /**
     * @var ExceptionValueMap
     */
    private $exceptionCodes;

    /**
     * @var bool
     */
    private $showException;

    public function __construct()
    {
        $this->showException = true;
    }

    /**
     * Converts an Exception to a Response.
     *
     * @param Request                   $request
     * @param \Exception|\Throwable     $exception
     * @param DebugLoggerInterface|null $logger
     *
     * @throws \InvalidArgumentException
     *
     * @return Response
     */
    public function showAction(Request $request, $exception, DebugLoggerInterface $logger = null)
    {
        $currentContent = $this->getAndCleanOutputBuffering($request->headers->get('X-Php-Ob-Level', -1));
        $code = $this->getStatusCode($exception);

        $errMessageArray = split('#showme#', $exception->getMessage());
        $errorMessage = $errMessageArray[0];
        $showMessage = count($errMessageArray) > 1 ? $errMessageArray[1] : '';

        $templateData = [
            'code' => $code,
            'error' => array_key_exists($code, Response::$statusTexts) ? Response::$statusTexts[$code] : 'client error',
            'error_description' => $errorMessage,
            'show_message' => $showMessage
        ];
        return new JsonResponse($templateData);
    }

    /**
     * Determines the status code to use for the response.
     *
     * @param \Exception $exception
     *
     * @return int
     */
    protected function getStatusCode(\Exception $exception)
    {
        if ($exception instanceof HttpExceptionInterface) {
            return $exception->getStatusCode();
        }

        return 500;
    }

    /**
     * Determines the template parameters to pass to the view layer.
     *
     * @param string               $currentContent
     * @param int                  $code
     * @param \Exception           $exception
     * @param DebugLoggerInterface $logger
     *
     * @return array
     */
    private function getTemplateData($currentContent, $code, \Exception $exception, DebugLoggerInterface $logger = null)
    {
        return [
            'exception' => FlattenException::create($exception),
            'status' => 'error',
            'status_code' => $code,
            'status_text' => array_key_exists($code, Response::$statusTexts) ? Response::$statusTexts[$code] : 'error',
            'currentContent' => $currentContent,
            'logger' => $logger,
        ];
    }

    /**
     * Gets and cleans any content that was already outputted.
     *
     * This code comes from Symfony and should be synchronized on a regular basis
     * see src/Symfony/Bundle/TwigBundle/Controller/ExceptionController.php
     *
     * @return string
     */
    private function getAndCleanOutputBuffering($startObLevel)
    {
        if (ob_get_level() <= $startObLevel) {
            return '';
        }
        Response::closeOutputBuffers($startObLevel + 1, true);

        return ob_get_clean();
    }

    /**
     * @return \FOS\RestBundle\Util\ExceptionValueMap;
     */
    private function getExceptionCodes()
    {
        return $this->container->get('fos_rest.exception.codes_map');
    }
}
