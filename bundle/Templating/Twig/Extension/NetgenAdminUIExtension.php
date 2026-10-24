<?php

namespace Netgen\Bundle\AdminUIBundle\Templating\Twig\Extension;

use Closure;
use eZExtension;
use eZPreferences;
use Netgen\Bundle\AdminUIBundle\Helper\PathHelper;
use Twig_Extension;
use Twig_SimpleFunction;

class NetgenAdminUIExtension extends Twig_Extension
{
    /**
     * @var \Netgen\Bundle\AdminUIBundle\Helper\PathHelper
     */
    protected $pathHelper;

    /**
     * @var \Closure
     */
    protected $legacyKernel;

    /**
     * @var string|null
     */
    protected $legacyJavaScriptLibrary;

    /**
     * Constructor.
     *
     * @param \Netgen\Bundle\AdminUIBundle\Helper\PathHelper $pathHelper
     * @param \Closure $legacyKernel
     */
    public function __construct(PathHelper $pathHelper, Closure $legacyKernel)
    {
        $this->pathHelper = $pathHelper;
        $this->legacyKernel = $legacyKernel;
    }

    /**
     * Returns the name of the extension.
     *
     * @return string The extension name
     */
    public function getName()
    {
        return 'netgen_admin_ui';
    }

    /**
     * Returns a list of functions to add to the existing list.
     *
     * @return array An array of functions
     */
    public function getFunctions()
    {
        return array(
            new Twig_SimpleFunction(
                'ngadmin_location_path',
                array($this, 'getLocationPath'),
                array('is_safe' => array('html'))
            ),
            new Twig_SimpleFunction(
                'ngadmin_ezpreference',
                array($this, 'getLegacyPreference')
            ),
            new Twig_SimpleFunction(
                'ngadmin_legacy_js_library',
                array($this, 'getLegacyJavaScriptLibrary')
            ),
        );
    }

    /**
     * Returns the path for specified location ID.
     *
     * @param mixed $locationId
     *
     * @return array
     */
    public function getLocationPath($locationId)
    {
        return $this->pathHelper->getPath($locationId);
    }

    /**
     * Returns eZ Publish Legacy ezpreference value.
     *
     * @param string $name
     *
     * @return mixed
     */
    public function getLegacyPreference($name)
    {
        $legacyKernel = $this->legacyKernel;

        return $legacyKernel()->runCallback(
            function () use ($name) {
                return eZPreferences::value($name);
            }
        );
    }

    /**
     * Returns the JavaScript library the legacy kernel provides for the admin widgets:
     * 'yui' when ezjscore still provides YUI (ezjsc::yui2), 'expui' when it does not and
     * Exponential UI (extension expui) is active, 'none' otherwise.
     *
     * The legacy templates of the ngadminui extension decide the same way
     * (ngadminui_js_library() template operator).
     *
     * @return string
     */
    public function getLegacyJavaScriptLibrary()
    {
        if ($this->legacyJavaScriptLibrary !== null) {
            return $this->legacyJavaScriptLibrary;
        }

        $legacyKernel = $this->legacyKernel;

        $this->legacyJavaScriptLibrary = $legacyKernel()->runCallback(
            function () {
                if (class_exists('ezjscServerFunctionsJs') && method_exists('ezjscServerFunctionsJs', 'yui2')) {
                    return 'yui';
                }

                return in_array('expui', eZExtension::activeExtensions(), true) ? 'expui' : 'none';
            }
        );

        return $this->legacyJavaScriptLibrary;
    }
}
