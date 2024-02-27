<template>
  <div class="flex flex-col">
    <!-- PreviewCard: Whats Happening -->
    <SidebarRightPreviewCard title="What's Happening">
      <SidebarRightPreviewCardItem
        v-for="trending in trends"
        :key="trending.id"
      >
        <div>
          <h2 class="font-bold text-gray-800 text-md dark:text-white">
            {{ trending.title }}
          </h2>
          <p class="text-xs text-gray-400">
            {{ trending.count }}
          </p>
        </div>
      </SidebarRightPreviewCardItem>
    </SidebarRightPreviewCard>
    <!-- PreviewCard: Who to follow -->
    <SidebarRightPreviewCard title="Who to follow">
      <SidebarRightPreviewCardItem
        v-for="quemSeguir in suggestions"
        :key="quemSeguir.id"
      >
        <div class="flex flex-row justify-between items-center p-2">
          <div class="flex flex-row">
            <img
              class="w-10 h-10 rounded-full"
              :src="quemSeguir.image"
              :alt="`Foto de perfil de ${quemSeguir.nome}`"
            />
            <div class="flex flex-col ml-2">
              <h1 class="font-bold text-gray-900 text-sm dark:text-white">
                {{ quemSeguir.name }}
              </h1>
              <p class="text-xs text-gray-400">
                {{ quemSeguir.handle }}
              </p>
            </div>
          </div>
          <div class="flex h-full">
            <button
              class="px-4 py-2 font-bold text-xs text-white dark:text-black bg-black dark:bg-white rounded-full"
            >
              Seguir
            </button>
          </div>
        </div>
      </SidebarRightPreviewCardItem>
    </SidebarRightPreviewCard>
  </div>
</template>

<script setup>
const trends = ref([
  {
    id: 1,
    title: "SpaceX",
    count: "18.8k Tweets",
  },
  {
    id: 2,
    title: "#CodingIsFun",
    count: "18.8k Tweets",
  },
  {
    id: 3,
    title: "#MakeTheL",
    count: "13k Tweets",
  },
]);

const suggestions = ref([
  {
    id: 1,
    name: "Pedro Hoffmann",
    handle: "@___hoffmann",
    image: "https://picsum.photos/200/200",
  },
  {
    id: 2,
    name: "Pedro Hoffmann",
    handle: "@___hoffmann",
    image: "https://picsum.photos/200/200",
  },
  {
    id: 3,
    name: "Pedro Hoffmann",
    handle: "@___hoffmann",
    image: "https://picsum.photos/200/200",
  },
]);
</script>
