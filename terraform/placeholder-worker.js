// Contenu jamais réellement servi : `wrangler deploy` écrase ce placeholder
// juste après la création de la ressource par Terraform (voir main.tf).
export default {
  async fetch() {
    return new Response("managed by wrangler, not terraform");
  },
};
