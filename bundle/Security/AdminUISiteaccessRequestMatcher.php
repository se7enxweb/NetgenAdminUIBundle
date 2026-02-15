<?php

namespace Netgen\Bundle\AdminUIBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

/**
 * Custom RequestMatcher for admin_ui firewall.
 * 
 * Matches requests to admin UI siteaccesses dynamically without hardcoding hostnames.
 * Reads admin siteaccess groups from ezplatform configuration.
 * 
 * Admin siteaccesses are defined in app/config/ezplatform_siteaccess.yml
 * under the siteaccess_groups admin_group configuration.
 */
class AdminUISiteaccessRequestMatcher implements RequestMatcherInterface
{
    /**
     * Siteaccess groups configuration (injected from services.yml)
     */
    private $siteaccessGroups;

    /**
     * Admin group names that should use the admin_ui firewall
     */
    private $adminGroupNames = ['ngadmin_group', 'admin_group'];

    public function __construct(array $siteaccessGroups)
    {
        $this->siteaccessGroups = $siteaccessGroups;
    }

    /**
     * Matches if the request is for an admin siteaccess
     *
     * @param Request $request
     * @return bool
     */
    public function matches(Request $request)
    {
        // Get the siteaccess that eZ Platform determined for this request
        $siteaccess = $request->attributes->get('siteaccess');
        
        if (!$siteaccess) {
            // No siteaccess set yet - let it pass, will be resolved later
            return false;
        }

        // Check if this siteaccess belongs to an admin group
        foreach ($this->adminGroupNames as $adminGroup) {
            if (isset($this->siteaccessGroups[$adminGroup]) && 
                in_array($siteaccess->name, $this->siteaccessGroups[$adminGroup], true)) {
                return true;
            }
        }

        return false;
    }
}
