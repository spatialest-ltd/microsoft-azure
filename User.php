<?php

namespace SocialiteProviders\Entra;

use SocialiteProviders\Manager\OAuth2\User as oAuth2User;

class User extends oAuth2User
{
    /**
     * The user's principal name.
     *
     * @var string
     */
    public $principalName;

    /**
     * The user's mail.
     *
     * @var string
     */
    public $mail;

    /**
     * The user's id token.
     *
     * @var string
     */
    public $idToken;

    /**
     * The user's roles.
     *
     * @var string[]
     */
    public $roles;

    /**
     * Get the principal name for the user.
     *
     * @return string
     */
    public function getPrincipalName()
    {
        return $this->principalName;
    }

    /**
     * Get the mail for the user.
     *
     * @return string
     */
    public function getMail()
    {
        return $this->mail;
    }

    /**
     * Get the id token for the user.
     *
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * Set the id token on the user.
     *
     * @param  string  $token
     * @return $this
     */
    public function setIdToken($idToken)
    {
        $this->idToken = $idToken;

        // decode the JWT id token
        list($header, $payload, $signature) = explode('.', $this->idToken);
        $jsonToken = base64_decode($payload);
        $arrayToken = json_decode($jsonToken, true);

        $this->roles = $arrayToken['roles'];

        return $this;
    }
}
