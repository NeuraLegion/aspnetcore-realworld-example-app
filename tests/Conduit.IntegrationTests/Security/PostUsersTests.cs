using System;
using System.Threading.Tasks;
using Xunit;
using SecTester.Core;
using SecTester.Runner;

namespace Conduit.IntegrationTests.Security
{
    public class PostUsersTests : IAsyncLifetime
    {
        private SecRunner _runner;
        private string _baseUrl;

        public async Task InitializeAsync()
        {
            var hostname = Environment.GetEnvironmentVariable("BRIGHT_HOSTNAME")!;
            var projectId = Environment.GetEnvironmentVariable("BRIGHT_PROJECT_ID")!;
            var config = new Configuration(hostname, projectId);
            _runner = await SecRunner.Create(config);
            await _runner.Init();

            // Start the application and set the base URL
            _baseUrl = "http://localhost:" + new Random().Next(5000, 6000); // Random port for example
            // Code to start the application should be added here
        }

        public async Task DisposeAsync()
        {
            await _runner.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        [Fact(Timeout = 40 * 60 * 1000)] // 40 minutes timeout
        public async Task PostUsersSecurityTest()
        {
            await _runner
                .CreateScan(new ScanSettings
                {
                    Tests = new[] { "csrf", "mass_assignment", "excessive_data_exposure", "xss", "sqli", "secret_tokens" },
                    AttackParamLocations = new[] { AttackParamLocation.BODY, AttackParamLocation.HEADER },
                    Threshold = Severity.CRITICAL,
                    Timeout = 40 * 60 * 1000, // 40 minutes
                    SkipStaticParams = false
                })
                .Run(new HttpRequest
                {
                    Method = HttpMethod.POST,
                    Url = $"{_baseUrl}/users",
                    Headers = new[] { new HttpHeader("Content-Type", "application/json") },
                    Body = new { user = new { username = "sampleuser", email = "sampleuser@example.com", password = "securepassword123" } }
                });
        }
    }
}
