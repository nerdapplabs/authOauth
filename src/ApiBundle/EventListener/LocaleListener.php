<?php

namespace ApiBundle\EventListener;

use FOS\RestBundle\FOSRestBundle;
use FOS\RestBundle\Util\StopFormatListenerException;
use FOS\RestBundle\Negotiation\FormatNegotiator;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Exception\NotAcceptableHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * This listener sets locale for all requests.
 *
 * @author Amarendra Kumar Sinha <aksinha@nerdapplabs.com>
 *
 */
class LocaleListener
{
    private $defaultLocale;
    private $appLocales;

    /**
     * Initialize LocaleListener.
     *
     * @param ContainerInterface $container
     */
    public function __construct($defaultLocale, $appLocales)
    {
      $this->defaultLocale = $defaultLocale;
      $this->appLocales = $appLocales;
    }

    /**
     * Determines and sets the Requested locale.
     *
     * @param GetResponseEvent $event The event
     */
    public function onKernelRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        // Construct $data per request method
        $method = $request->getMethod();
        if ('GET' === $method) {
         $data = $request->query->all();
        } else {
         $data = $request->request->all();
        }

        // Set locale to app default locale
        $locale = $this->defaultLocale;

        // Get permitted app locales
        $permittedLocales = explode("|", $this->appLocales);
        $requestedLocale = array_key_exists('_locale', $data) ? $data['_locale'] : null;

        // If requested locale is among the permitted locales by the app, then set $locale
        // to the requested locale, otherwise set it to the app default locale.
        if ($requestedLocale ) {
            if (in_array($requestedLocale, $permittedLocales)) {
              $locale = $requestedLocale;
            }
        }

        // Set request locale to the calculated one
        $request->setLocale($locale);
        // die($requestedLocale . ' ' . $request->getLocale($locale));
    }
}
