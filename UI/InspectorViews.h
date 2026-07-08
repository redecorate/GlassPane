#pragma once

// Inspector view rendering is implemented in UI/InspectorViews.cpp and included
// inside the private ImGuiApp class definition. This keeps state ownership in
// ImGuiApp while reducing the size of UI/ImGuiApp.cpp.

