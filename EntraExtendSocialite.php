<?php

namespace SocialiteProviders\Entra;

use SocialiteProviders\Manager\SocialiteWasCalled;

class EntraExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('entra', Provider::class);
    }
}
