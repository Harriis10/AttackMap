using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

internal static class UiActivation
{
    internal static bool IsEffectivelyVisible(DependencyObject element)
    {
        var current = element;
        for (int depth = 0; depth < 64; ++depth)
        {
            if (current is UIElement ui && ui.Visibility != Visibility.Visible) return false;
            if (current is FrameworkElement framework &&
                (!framework.IsLoaded || framework.ActualWidth <= 0 || framework.ActualHeight <= 0)) return false;
            var parent = VisualTreeHelper.GetParent(current);
            if (parent is null) return current is FrameworkElement { XamlRoot: not null };
            current = parent;
        }
        return false;
    }

    internal static object Describe(DependencyObject element)
    {
        var ancestry = new List<object>();
        var current = element;
        for (int depth = 0; depth < 64; ++depth)
        {
            var parent = VisualTreeHelper.GetParent(current);
            ancestry.Add(new
            {
                type = current.GetType().Name,
                visibility = (current as UIElement)?.Visibility.ToString(),
                loaded = (current as FrameworkElement)?.IsLoaded,
                width = (current as FrameworkElement)?.ActualWidth,
                height = (current as FrameworkElement)?.ActualHeight,
                hasXamlRoot = (current as FrameworkElement)?.XamlRoot != null,
                hasParent = parent != null
            });
            if (parent is null) return new { visible = IsEffectivelyVisible(element), ancestry };
            current = parent;
        }
        return new { visible = IsEffectivelyVisible(element), ancestry, bounded = true };
    }
}
