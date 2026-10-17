using System.Text.Json;
using Microsoft.UI.Xaml;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private void ResetAiReview()
    {
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(AiReviewButton, "Read saved AI review from the selected run; no provider request");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(AiReviewText, "Saved selected-run AI review; unverified model prose");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetLiveSetting(AiReviewStatus, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        AiReviewText.Text = "";
        AiReviewStatus.Text = "No AI review loaded. AI is off by default; a review exists only when explicitly generated for the selected run.";
    }

    private async void OpenAiReview(object sender, RoutedEventArgs args)
    {
        var selected = exportSelection;
        long selectedGeneration = generation;
        ResetAiReview();
        if (selected == null || !selected.Verified)
        {
            AiReviewStatus.Text = "A verified selected generation is required to read its AI artifacts. Legacy imports retain canonical report viewing; their adjacent AI files have unverified identity.";
            return;
        }
        AiReviewButton.IsEnabled = false;
        AiReviewStatus.Text = "Reading this selected generation only…";
        try
        {
            var records = await Task.Run(() => SelectedArtifacts.List(selected));
            var review = records.SingleOrDefault(record => Path.GetFileName(record.FullPath) == "defensive-review-llm.md");
            if (actionLifetime.IsCancellationRequested || exportSelection != selected || generation != selectedGeneration) return;
            if (review == null)
            {
                AiReviewStatus.Text = "No AI review was generated for this selected run. Local scans work with AI off. Enabling AI later does not generate a review retroactively.";
                return;
            }
            string prose = await SelectedArtifacts.ReadText(selected, review);
            string model = "Model unavailable (metadata not supplied)", backend = "Backend unavailable";
            var metadata = records.SingleOrDefault(record => Path.GetFileName(record.FullPath) == "defensive-review-llm.meta.json");
            if (metadata != null)
            {
                string supplied = await SelectedArtifacts.ReadText(selected, metadata, 1024 * 1024);
                using var document = JsonDocument.Parse(supplied);
                string? Field(string name) => document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                model = Field("model") ?? model;
                backend = Field("backend") ?? backend;
            }
            if (actionLifetime.IsCancellationRequested || exportSelection != selected || generation != selectedGeneration) return;
            AiReviewStatus.Text = $"Selected run: {selected.RunId}\nModel (as supplied): {model}; backend (as supplied): {backend}\nArtifact identity and bytes verified against this selected manifest. Generated prose remains unverified; metadata is not runtime proof. The complete supplied review and scope notice follow as inert text.";
            AiReviewText.Text = prose;
        }
        catch (Exception)
        {
            if (!actionLifetime.IsCancellationRequested && exportSelection == selected && generation == selectedGeneration)
            {
                AiReviewText.Text = "";
                AiReviewStatus.Text = "AI review could not be read: selected files changed, metadata is malformed, or the text exceeds the preview limit. Reopen the report and try again. No provider request was made.";
            }
        }
        finally { if (!actionLifetime.IsCancellationRequested) AiReviewButton.IsEnabled = true; }
    }
}
