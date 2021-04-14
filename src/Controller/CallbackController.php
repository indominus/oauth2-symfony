<?php

namespace App\Controller;

use Exception;
use App\Services\OAuth2\GenericProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class CallbackController extends AbstractController
{
    /**
     * @Route("/callback", name="app.callback")
     *
     * @param Request $request
     * @param SessionInterface $session
     * @param GenericProvider $provider
     *
     * @return Response
     */
    public function index(Request $request, SessionInterface $session, GenericProvider $provider)
    {

        try {

            if ($session->get('oauth2_state', false) !== $request->query->get('state', null)) {
                throw new Exception('Invalid state');
            }

            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $request->query->get('code', null)
            ]);

            $session->set('accessToken', $accessToken->jsonSerialize());

        } catch (IdentityProviderException | Exception $e) {
            $this->addFlash('errors', $e->getMessage());
        }

        return new RedirectResponse($this->generateUrl('homepage'));
    }
}
