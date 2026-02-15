<?php

declare(strict_types=1);

namespace Netgen\Bundle\AdminUIBundle\Service;

/**
 * Centralized configuration service for Admin UI
 * Single source of truth for all path, location, and authentication configuration
 * Eliminates hardcoded values throughout EventListener classes
 */
class AdminUIConfiguration
{
    /**
     * Admin siteaccess group names (fetched from config)
     */
    private array $adminGroupNames;

    /**
     * Security and routing paths
     */
    private string $loginPath;
    private string $loginCheckPath;
    private string $logoutPath;
    private string $dashboardPath;
    private string $rootPath;
    private string $searchRoutePath;

    /**
     * Authentication configuration
     */
    private string $basicAuthScheme;

    /**
     * Paths that do NOT require authentication
     */
    private array $publicPaths;

    /**
     * Content location node IDs for shortcuts
     */
    private int $mediaLocationId;
    private int $designLocationId;
    private int $usersLocationId;

    /**
     * Constructor with sensible defaults
     * Can be overridden via bundle configuration or DI container parameters
     *
     * @param array $config Configuration array with optional overrides
     */
    public function __construct(array $config = [])
    {
        // Admin siteaccess group names - CENTRALIZED (removes duplication)
        // Default: admin_group, ngadmin_group, legacy_group
        $this->adminGroupNames = $config['admin_group_names'] ?? [
            'admin_group',
            'ngadmin_group',
            'legacy_group',
        ];

        // Security-critical paths
        $this->loginPath = $config['login_path'] ?? '/login';
        $this->loginCheckPath = $config['login_check_path'] ?? '/login_check';
        $this->logoutPath = $config['logout_path'] ?? '/logout';
        $this->dashboardPath = $config['dashboard_path'] ?? '/content/dashboard';
        $this->rootPath = $config['root_path'] ?? '/';
        $this->searchRoutePath = $config['search_route_path'] ?? '/content/search';

        // Authentication configuration
        $this->basicAuthScheme = $config['basic_auth_scheme'] ?? 'Basic ';

        // Public paths (accessible without authentication)
        $this->publicPaths = $config['public_paths'] ?? [
            '/',
            '/login',
            '/logout',
            '/login_check',
            '/extension/',    // Static assets
            '/design/',       // Static assets
            '/var/storage/',  // Media storage files
            '/image/',        // Image handler
            '/bundles/',      // Bundle assets
        ];

        // Content location node IDs for shortcuts
        $this->mediaLocationId = $config['media_location'] ?? 43;
        $this->designLocationId = $config['design_location'] ?? 58;
        $this->usersLocationId = $config['users_location'] ?? 5;
    }

    /**
     * Get all admin group names
     */
    public function getAdminGroupNames(): array
    {
        return $this->adminGroupNames;
    }

    /**
     * Check if a group name is an admin group
     * REPLACES: in_array($groupName, ['admin_group', ...], true)
     */
    public function isAdminGroupName(string $groupName): bool
    {
        return in_array($groupName, $this->adminGroupNames, true);
    }

    // ========== Authentication Paths ==========

    /**
     * Get login page path
     */
    public function getLoginPath(): string
    {
        return $this->loginPath;
    }

    /**
     * Get login check form submission path
     */
    public function getLoginCheckPath(): string
    {
        return $this->loginCheckPath;
    }

    /**
     * Get logout path
     */
    public function getLogoutPath(): string
    {
        return $this->logoutPath;
    }

    /**
     * Get dashboard redirect path
     */
    public function getDashboardPath(): string
    {
        return $this->dashboardPath;
    }

    /**
     * Get root path
     */
    public function getRootPath(): string
    {
        return $this->rootPath;
    }

    /**
     * Check if path is login page
     * REPLACES: $pathInfo === '/login'
     */
    public function isLoginPath(string $path): bool
    {
        return $path === $this->loginPath;
    }

    /**
     * Check if path is login check (form submission)
     * REPLACES: $pathInfo === '/login_check'
     */
    public function isLoginCheckPath(string $path): bool
    {
        return $path === $this->loginCheckPath;
    }

    /**
     * Check if path is logout
     * REPLACES: $pathInfo === '/logout'
     */
    public function isLogoutPath(string $path): bool
    {
        return $path === $this->logoutPath;
    }

    /**
     * Check if path is root
     * REPLACES: $pathInfo === '/'
     */
    public function isRootPath(string $path): bool
    {
        return $path === $this->rootPath;
    }

    /**
     * Check if path is authentication-related (login/logout/check)
     */
    public function isAuthPath(string $path): bool
    {
        return $this->isLoginPath($path) || 
               $this->isLogoutPath($path) || 
               $this->isLoginCheckPath($path);
    }

    // ========== Search Route ==========

    /**
     * Get search route path prefix
     */
    public function getSearchRoutePath(): string
    {
        return $this->searchRoutePath;
    }

    /**
     * Check if path is search route
     * REPLACES: strpos($pathInfo, '/content/search') === 0
     */
    public function isSearchRoute(string $path): bool
    {
        return strpos($path, $this->searchRoutePath) === 0;
    }

    // ========== Public Paths ==========

    /**
     * Get all public paths (no auth required)
     */
    public function getPublicPaths(): array
    {
        return $this->publicPaths;
    }

    /**
     * Check if path is public (no authentication required)
     * REPLACES: checking hardcoded $publicPaths array
     */
    public function isPublicPath(string $path): bool
    {
        foreach ($this->publicPaths as $publicPath) {
            // Exact match or prefix match
            if ($path === $publicPath || strpos($path, $publicPath) === 0) {
                return true;
            }
        }
        return false;
    }

    // ========== Authentication Configuration ==========

    /**
     * Get Basic auth scheme header value
     */
    public function getBasicAuthScheme(): string
    {
        return $this->basicAuthScheme;
    }

    /**
     * Check if header is Basic authentication
     * REPLACES: strpos($authHeader, 'Basic ') === 0
     */
    public function isBasicAuthHeader(string $authHeader): bool
    {
        return strpos($authHeader, $this->basicAuthScheme) === 0;
    }

    // ========== Content Locations ==========

    /**
     * Get media folder location node ID
     */
    public function getMediaLocationId(): int
    {
        return $this->mediaLocationId;
    }

    /**
     * Get design root location node ID
     */
    public function getDesignLocationId(): int
    {
        return $this->designLocationId;
    }

    /**
     * Get users folder location node ID
     */
    public function getUsersLocationId(): int
    {
        return $this->usersLocationId;
    }

    /**
     * Get all shortcuts with location IDs
     * REPLACES: hardcoded $shortcuts array in NavigationInterceptor
     */
    public function getShortcuts(): array
    {
        return [
            '/Media' => '/content/view/full/' . $this->mediaLocationId,
            '/Design' => '/content/view/full/' . $this->designLocationId,
            '/Users' => '/content/view/full/' . $this->usersLocationId,
        ];
    }
}
