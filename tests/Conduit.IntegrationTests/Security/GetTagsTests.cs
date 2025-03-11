using System;
using System.Threading.Tasks;
using Xunit;
using SecTester.Core;
using SecTester.Runner;
using SecTester.Scan;

namespace Conduit.IntegrationTests.Security
{
    public class GetTagsTests : IAsyncLifetime
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
        public async Task TestGetTagsEndpoint()
        {
            await _runner
                .CreateScan(new ScanSettings
                {
                    Tests = new[] { "csrf", "excessive_data_exposure", "http_method_fuzzing", "mass_assignment" },
                    AttackParamLocations = new[] { AttackParamLocation.QUERY },
                    Threshold = Severity.CRITICAL,
                    Timeout = TimeSpan.FromMinutes(40)
                })
                .Run(new ScanOptions
                {
                    Method = HttpMethod.GET,
                    Url = $"{_baseUrl}/tags"
                });
        }
    }
}
